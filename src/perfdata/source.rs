use std::collections::BTreeMap;
use std::fs::File;
#[cfg(not(unix))]
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::FileExt;

use super::records::{PerfRecord, parse_record_header};

pub(super) trait RecordSource {
    fn len(&self) -> usize;
    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String>;

    fn retain_record(&mut self, _offset: usize) -> Result<(), String> {
        Ok(())
    }

    fn release_record(&mut self, _offset: usize) {}

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

struct FileWindow<'a> {
    file: &'a File,
    len: usize,
    buffer: Vec<u8>,
    start: usize,
    valid: usize,
    read_size: usize,
    #[cfg(test)]
    bytes_read: usize,
}

impl<'a> FileWindow<'a> {
    fn new(file: &'a File, read_size: usize) -> Result<Self, String> {
        let len = usize::try_from(
            file.metadata()
                .map_err(|error| format!("failed to stat perf.data: {error}"))?
                .len(),
        )
        .map_err(|_| "perf.data size exceeds usize".to_string())?;
        Ok(Self {
            file,
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

impl RecordSource for FileWindow<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= self.len)
            .ok_or_else(|| format!("truncated perf record at offset {offset}"))?;
        if offset < self.start || end > self.start + self.valid {
            // A failed read can partially overwrite the buffer, so its old
            // range must stop being readable before starting the refill.
            self.valid = 0;
            let size = self.read_size.max(len).min(self.len - offset);
            if self.buffer.len() < size {
                self.buffer.resize(size, 0);
            }
            #[cfg(unix)]
            self.file
                .read_exact_at(&mut self.buffer[..size], offset as u64)
                .map_err(|error| format!("failed to read perf record: {error}"))?;
            #[cfg(not(unix))]
            {
                self.file
                    .seek(SeekFrom::Start(offset as u64))
                    .map_err(|error| format!("failed to seek perf record: {error}"))?;
                self.file
                    .read_exact(&mut self.buffer[..size])
                    .map_err(|error| format!("failed to read perf record: {error}"))?;
            }
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

const DELIVERY_RANGE_SIZE: usize = 4 * 1024 * 1024;

struct QueuedRange {
    bytes: memmap2::Mmap,
    pending: usize,
}

// perf's session.c:reader__mmap and ordered-events.c:dup_event/do_flush keep
// event backing valid until ordered delivery. Here queued records retain file
// ranges instead of owning copied payloads or rereading each record.
struct MappedDelivery<'a> {
    file: &'a File,
    len: usize,
    ranges: BTreeMap<usize, QueuedRange>,
    current: Option<usize>,
    #[cfg(test)]
    mappings_created: usize,
}

impl MappedDelivery<'_> {
    fn range_start(offset: usize) -> usize {
        offset / DELIVERY_RANGE_SIZE * DELIVERY_RANGE_SIZE
    }
}

impl RecordSource for MappedDelivery<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= self.len)
            .ok_or_else(|| format!("truncated perf record at offset {offset}"))?;
        let start = Self::range_start(offset);
        if self
            .ranges
            .get(&start)
            .is_none_or(|range| range.bytes.len() < end - start)
        {
            // Overlap by a maximum-sized record so even a header at the range
            // boundary and its payload have one contiguous borrowed backing.
            let size = (DELIVERY_RANGE_SIZE + usize::from(u16::MAX))
                .max(end - start)
                .min(self.len - start);
            // SAFETY: Replay reads a completed perf.data that must remain
            // unmodified and untruncated while this source exists. Mmap owns
            // the read-only view; borrows cannot outlive it or coexist with
            // mutable source access that removes/replaces the range.
            let bytes = unsafe {
                memmap2::MmapOptions::new()
                    .offset(start as u64)
                    .len(size)
                    .map(self.file)
            }
            .map_err(|error| format!("failed to map perf record backing: {error}"))?;
            let pending = self.ranges.get(&start).map_or(0, |range| range.pending);
            self.ranges.insert(start, QueuedRange { bytes, pending });
            #[cfg(test)]
            {
                self.mappings_created += 1;
            }
        }
        if let Some(previous) = self.current.replace(start).filter(|old| *old != start)
            && self
                .ranges
                .get(&previous)
                .is_some_and(|range| range.pending == 0)
        {
            self.ranges.remove(&previous);
        }
        Ok(&self.ranges[&start].bytes[offset - start..end - start])
    }

    fn retain_record(&mut self, offset: usize) -> Result<(), String> {
        self.bytes_at(offset, 8)?;
        self.ranges
            .get_mut(&Self::range_start(offset))
            .expect("record backing was just mapped")
            .pending += 1;
        Ok(())
    }

    fn release_record(&mut self, offset: usize) {
        let start = Self::range_start(offset);
        let range = self
            .ranges
            .get_mut(&start)
            .expect("queued record backing remains mapped until delivery");
        range.pending -= 1;
        if range.pending == 0 {
            self.ranges.remove(&start);
            if self.current == Some(start) {
                self.current = None;
            }
        }
    }
}

pub(super) struct FileSource<'a> {
    scan: FileWindow<'a>,
    delivery: MappedDelivery<'a>,
}

impl<'a> FileSource<'a> {
    pub fn new(file: &'a File) -> Result<Self, String> {
        let scan = FileWindow::new(file, 1024 * 1024)?;
        Ok(Self {
            delivery: MappedDelivery {
                file,
                len: scan.len,
                ranges: BTreeMap::new(),
                current: None,
                #[cfg(test)]
                mappings_created: 0,
            },
            scan,
        })
    }

    #[cfg(test)]
    fn bytes_read(&self) -> usize {
        self.scan.bytes_read
    }
}

impl RecordSource for FileSource<'_> {
    fn len(&self) -> usize {
        self.scan.len()
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        self.scan.bytes_at(offset, len)
    }

    fn delivered_record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        self.delivery.record_at(offset, end)
    }

    fn retain_record(&mut self, offset: usize) -> Result<(), String> {
        self.delivery.retain_record(offset)
    }

    fn release_record(&mut self, offset: usize) {
        self.delivery.release_record(offset);
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
    fn queued_delivery_reuses_input_backing_when_timestamp_order_alternates_file_runs() {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let near = record(b"near");
        let far = 32 * 1024 * 1024;
        file.write_all(&near).unwrap();
        file.seek(SeekFrom::Start(far as u64)).unwrap();
        file.write_all(&record(b"far")).unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for offset in [0, far] {
            source.record_at(offset, source.len()).unwrap();
            for _ in 0..16 {
                source.retain_record(offset).unwrap();
            }
        }
        let copied_before_delivery = source.bytes_read();
        for _ in 0..16 {
            for (offset, expected) in [(far, &b"far"[..]), (0, &b"near"[..])] {
                assert_eq!(
                    source
                        .delivered_record_at(offset, source.len())
                        .unwrap()
                        .payload,
                    expected
                );
                source.release_record(offset);
            }
        }
        assert_eq!(
            source.bytes_read(),
            copied_before_delivery,
            "timestamp-ordered delivery must not copy or reread retained record backing"
        );
        assert_eq!(source.delivery.mappings_created, 2);
        assert!(source.delivery.ranges.is_empty());
    }

    #[test]
    fn queued_ranges_are_released_at_their_last_delivery_not_at_a_cache_limit() {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let offsets = [
            0,
            super::DELIVERY_RANGE_SIZE,
            3 * super::DELIVERY_RANGE_SIZE,
        ];
        for offset in offsets {
            file.seek(SeekFrom::Start(offset as u64)).unwrap();
            file.write_all(&record(b"pending")).unwrap();
        }
        let mut source = FileSource::new(file.as_file()).unwrap();
        for offset in offsets {
            source.retain_record(offset).unwrap();
        }
        source.retain_record(0).unwrap();
        assert_eq!(source.delivery.ranges.len(), 3);
        for (offset, remaining_ranges) in [(offsets[2], 2), (0, 2), (offsets[1], 1), (0, 0)] {
            assert_eq!(
                source
                    .delivered_record_at(offset, source.len())
                    .unwrap()
                    .payload,
                b"pending"
            );
            source.release_record(offset);
            assert_eq!(source.delivery.ranges.len(), remaining_ranges);
        }
        assert_eq!(source.delivery.mappings_created, 3);
        assert!(source.delivery.current.is_none());
    }

    #[test]
    fn queued_maximum_record_and_split_header_have_contiguous_backing_across_range_edges() {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let first = super::DELIVERY_RANGE_SIZE - 4;
        let large = record(&vec![7; usize::from(u16::MAX) - 8]);
        file.seek(SeekFrom::Start(first as u64)).unwrap();
        file.write_all(&large).unwrap();
        let second = first + large.len();
        file.write_all(&record(b"tail")).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for offset in [first, second] {
            source.record_at(offset, source.len()).unwrap();
            source.retain_record(offset).unwrap();
        }
        for (offset, expected) in [(second, &b"tail"[..]), (first, &large[8..])] {
            assert_eq!(
                source
                    .delivered_record_at(offset, source.len())
                    .unwrap()
                    .payload,
                expected
            );
            source.release_record(offset);
        }
        assert_eq!(source.delivery.mappings_created, 2);
        assert!(source.delivery.ranges.is_empty());
    }

    #[test]
    fn invalid_mapped_delivery_ranges_do_not_corrupt_pending_backing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), record(b"retained")).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.retain_record(0).unwrap();
        assert!(source.delivery.bytes_at(usize::MAX, 8).is_err());
        assert!(source.delivery.bytes_at(source.len() - 4, 8).is_err());
        assert!(source.delivered_record_at(0, 8).is_err());
        assert_eq!(source.delivery.ranges.len(), 1);
        assert_eq!(
            source.delivered_record_at(0, source.len()).unwrap().payload,
            b"retained"
        );
        source.release_record(0);
        assert!(source.delivery.ranges.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn file_windows_read_by_offset_without_moving_the_callers_cursor() {
        use std::io::{Seek, SeekFrom};
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = record(b"first");
        let far = 128 * 1024;
        bytes.resize(far, 0);
        bytes.extend(record(b"last"));
        std::fs::write(file.path(), &bytes).unwrap();
        let mut cursor = file.as_file();
        cursor.seek(SeekFrom::Start(3)).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for (offset, expected) in [(0, &b"first"[..]), (far, &b"last"[..]), (0, &b"first"[..])] {
            assert_eq!(
                source.record_at(offset, bytes.len()).unwrap().payload,
                expected
            );
            assert_eq!(cursor.stream_position().unwrap(), 3);
            assert_eq!(
                source
                    .delivered_record_at(offset, bytes.len())
                    .unwrap()
                    .payload,
                expected
            );
            assert_eq!(cursor.stream_position().unwrap(), 3);
        }
    }

    #[test]
    fn failed_refill_cannot_reuse_partially_overwritten_cached_bytes() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = b"abcdefghijklmnop".to_vec();
        bytes.resize(32, 0);
        bytes.extend(b"XY");
        std::fs::write(file.path(), &bytes).unwrap();
        file.as_file().set_len(64).unwrap();
        let mut window = super::FileWindow::new(file.as_file(), 16).unwrap();
        assert_eq!(window.bytes_at(0, 2).unwrap(), b"ab");
        file.as_file().set_len(34).unwrap();
        assert!(window.bytes_at(32, 16).is_err());
        assert_eq!(window.bytes_at(0, 2).unwrap(), b"ab");
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
