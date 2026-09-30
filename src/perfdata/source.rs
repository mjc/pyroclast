use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::records::{PerfRecord, parse_record_header};

pub(super) trait RecordSource {
    fn len(&self) -> usize;
    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String>;

    fn delivered_record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        self.record_at(offset, end)
    }

    fn record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        if offset.checked_add(8).is_none_or(|next| next > end) {
            return Err(format!("truncated perf record header at offset {offset}"));
        }
        let header = parse_record_header(self.bytes_at(offset, 8)?)?;
        let size = usize::from(header.size);
        if size < 8 {
            return Err(format!(
                "invalid perf record size {size} at offset {offset}"
            ));
        }
        if offset.checked_add(size).is_none_or(|next| next > end) {
            return Err(format!(
                "perf record overruns data section at offset {offset}"
            ));
        }
        Ok(PerfRecord {
            offset,
            header,
            payload: &self.bytes_at(offset, size)?[8..],
        })
    }
}

pub(super) struct SliceSource<'a>(pub &'a [u8]);

impl RecordSource for SliceSource<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        offset
            .checked_add(len)
            .and_then(|end| self.0.get(offset..end))
            .ok_or_else(|| format!("truncated perf record at offset {offset}"))
    }
}

struct FileWindow {
    file: File,
    len: usize,
    buffer: Vec<u8>,
    start: usize,
    valid: usize,
    read_size: usize,
    #[cfg(test)]
    bytes_read: usize,
}

impl FileWindow {
    fn new(file: &File, read_size: usize) -> Result<Self, String> {
        let len = usize::try_from(
            file.metadata()
                .map_err(|error| format!("failed to stat perf.data: {error}"))?
                .len(),
        )
        .map_err(|_| "perf.data size exceeds usize".to_string())?;
        Ok(Self {
            file: file
                .try_clone()
                .map_err(|error| format!("failed to clone perf.data: {error}"))?,
            len,
            // A reusable read window, not a cache of the recording. Ordered
            // delivery can revisit offsets without retaining record payloads.
            buffer: vec![0; read_size],
            read_size,
            start: 0,
            valid: 0,
            #[cfg(test)]
            bytes_read: 0,
        })
    }
}

impl RecordSource for FileWindow {
    fn len(&self) -> usize {
        self.len
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= self.len)
            .ok_or_else(|| format!("truncated perf record at offset {offset}"))?;
        if offset < self.start || end > self.start + self.valid {
            self.file
                .seek(SeekFrom::Start(offset as u64))
                .map_err(|error| format!("failed to seek perf record: {error}"))?;
            let size = self.read_size.max(len).min(self.len - offset);
            if self.buffer.len() < size {
                self.buffer.resize(size, 0);
            }
            self.file
                .read_exact(&mut self.buffer[..size])
                .map_err(|error| format!("failed to read perf record: {error}"))?;
            #[cfg(test)]
            {
                self.bytes_read += size;
            }
            self.start = offset;
            self.valid = size;
        }
        Ok(&self.buffer[offset - self.start..end - self.start])
    }
}

pub(super) struct FileSource {
    scan: FileWindow,
    delivery: FileWindow,
}

impl FileSource {
    pub fn new(file: &File) -> Result<Self, String> {
        Ok(Self {
            scan: FileWindow::new(file, 1024 * 1024)?,
            delivery: FileWindow::new(file, 4096)?,
        })
    }

    #[cfg(test)]
    fn bytes_read(&self) -> usize {
        self.scan.bytes_read + self.delivery.bytes_read
    }
}

impl RecordSource for FileSource {
    fn len(&self) -> usize {
        self.scan.len()
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        self.scan.bytes_at(offset, len)
    }

    fn delivered_record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        self.delivery.record_at(offset, end)
    }
}

#[cfg(test)]
mod tests {
    use super::{FileSource, RecordSource, SliceSource};

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(68_u32.to_le_bytes());
        bytes.extend(0_u16.to_le_bytes());
        bytes.extend(u16::try_from(payload.len() + 8).unwrap().to_le_bytes());
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn slice_and_file_sources_match_across_window_edges_and_backward_delivery() {
        let mut bytes = vec![0; 1024 * 1024 - 4];
        let first = bytes.len();
        bytes.extend(record(&vec![1; 65527]));
        let second = bytes.len();
        bytes.extend(record(b"second"));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let mut disk = FileSource::new(file.as_file()).unwrap();
        // Prime the old window so the first header straddles its boundary.
        disk.bytes_at(0, 8).unwrap();
        let mut memory = SliceSource(&bytes);
        for offset in [first, second, first, second] {
            let expected = memory.record_at(offset, bytes.len()).unwrap();
            let actual = disk.record_at(offset, bytes.len()).unwrap();
            assert_eq!(actual.offset, expected.offset);
            assert_eq!(actual.header, expected.header);
            assert_eq!(actual.payload, expected.payload);
        }
        assert_eq!(disk.scan.buffer.len(), 1024 * 1024);
    }

    #[test]
    fn file_source_storage_is_independent_of_recording_size() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for offset in [0, 32 * 1024 * 1024, source.len() - 8, 0] {
            assert_eq!(source.bytes_at(offset, 8).unwrap(), [0; 8]);
            assert_eq!(source.scan.buffer.len(), 1024 * 1024);
            assert_eq!(source.scan.buffer.capacity(), 1024 * 1024);
        }
    }

    #[test]
    fn ordered_delivery_does_not_repeatedly_copy_the_sequential_read_window() {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let bytes = record(b"");
        file.write_all(&bytes).unwrap();
        let far = 32 * 1024 * 1024;
        file.seek(SeekFrom::Start(far as u64)).unwrap();
        file.write_all(&bytes).unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.record_at(0, source.len()).unwrap();
        for _ in 0..16 {
            for offset in [far, 0] {
                source.delivered_record_at(offset, source.len()).unwrap();
            }
        }
        assert!(
            source.bytes_read() <= 2 * 1024 * 1024,
            "copied {} bytes to deliver 32 eight-byte records",
            source.bytes_read()
        );
    }

    #[test]
    fn source_parses_only_requested_records_before_a_later_bad_header() {
        let mut bytes = record(b"");
        bytes.extend(68_u32.to_le_bytes());
        bytes.extend(0_u16.to_le_bytes());
        bytes.extend(4_u16.to_le_bytes());
        let mut source = SliceSource(&bytes);
        assert_eq!(source.record_at(0, bytes.len()).unwrap().header.size, 8);
        assert_eq!(
            source.record_at(8, bytes.len()).unwrap_err(),
            "invalid perf record size 4 at offset 8"
        );
    }

    #[test]
    fn record_header_and_payload_cannot_cross_data_section_into_features() {
        let bytes = record(b"payload");
        let mut source = SliceSource(&bytes);
        assert_eq!(
            source.record_at(0, 4).unwrap_err(),
            "truncated perf record header at offset 0"
        );
        assert_eq!(
            source.record_at(0, 8).unwrap_err(),
            "perf record overruns data section at offset 0"
        );
        assert!(source.bytes_at(usize::MAX, 8).is_err());
    }

    #[test]
    fn file_source_reports_truncated_ranges_without_overflow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        assert!(source.bytes_at(0, 8).is_err());
        assert!(source.bytes_at(usize::MAX, 8).is_err());
    }
}
