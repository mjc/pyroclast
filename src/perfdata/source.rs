use std::fs::File;
#[cfg(not(unix))]
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use super::records::{PerfRecord, PerfRecordHeader, parse_record_header};

pub(super) struct QueuedPerfRecord {
    pub offset: usize,
    pub(super) window: usize,
}

struct ReadWindow {
    start: usize,
    bytes: Arc<Vec<u8>>,
}

#[derive(Default)]
pub(super) struct WindowStore {
    windows: Vec<Option<ReadWindow>>,
    refs: Vec<usize>,
    free: Vec<usize>,
    last: Option<(usize, usize)>,
}

impl WindowStore {
    pub(super) fn retain_with(
        &mut self,
        start: usize,
        backing: impl FnOnce() -> Arc<Vec<u8>>,
    ) -> usize {
        // replay_records queues in file order, so only the most recent window
        // can receive another queued record.
        if let Some((last_start, slot)) = self.last {
            if last_start == start && self.windows[slot].is_some() {
                self.refs[slot] += 1;
                return slot;
            }
            if self.refs[slot] == 0 {
                self.windows[slot] = None;
                self.free.push(slot);
            }
        }
        let slot = self.free.pop().unwrap_or_else(|| {
            self.windows.push(None);
            self.refs.push(0);
            self.windows.len() - 1
        });
        self.windows[slot] = Some(ReadWindow {
            start,
            bytes: backing(),
        });
        self.refs[slot] = 1;
        self.last = Some((start, slot));
        slot
    }

    pub(super) fn record(&self, queued: &QueuedPerfRecord) -> PerfRecord<'_> {
        let backing = self.windows[queued.window]
            .as_ref()
            .expect("queued record retains its read window");
        let start = queued.offset - backing.start;
        let header = parse_record_header(&backing.bytes[start..])
            .expect("queued record header was validated before retaining its immutable window");
        PerfRecord {
            offset: queued.offset,
            header,
            payload: &backing.bytes[start + 8..start + usize::from(header.size)],
        }
    }

    pub(super) fn release(&mut self, queued: &QueuedPerfRecord) {
        let slot = queued.window;
        self.refs[slot] -= 1;
        if self.refs[slot] == 0 && self.last.is_none_or(|(_, last_slot)| last_slot != slot) {
            self.windows[slot] = None;
            self.free.push(slot);
        }
    }
}

pub(super) trait RecordSource {
    fn len(&self) -> usize;
    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String>;

    fn queue_record(
        &mut self,
        offset: usize,
        end: usize,
        _header: PerfRecordHeader,
        windows: &mut WindowStore,
    ) -> Result<QueuedPerfRecord, String> {
        let size = self.record_at(offset, end)?.header.size;
        let bytes = self.bytes_at(offset, usize::from(size))?.to_vec();
        let window = windows.retain_with(offset, || Arc::new(bytes));
        Ok(QueuedPerfRecord { offset, window })
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

const SCAN_WINDOW_SIZE: usize = 4 * 1024 * 1024;

fn record_from_window(
    source: &mut impl RecordSource,
    offset: usize,
    end: usize,
) -> Result<PerfRecord<'_>, String> {
    let header_end = offset
        .checked_add(8)
        .filter(|next| *next <= end)
        .ok_or_else(|| format!("truncated perf record header at offset {offset}"))?;
    // session.c:prefetch_event checks header and payload in one backing.
    // Scan ranges overlap by a maximum u16-sized record, keeping every record
    // contiguous even when its header or payload crosses a window boundary.
    let window_end = offset
        .saturating_add(usize::from(u16::MAX))
        .min(end)
        .min(source.len())
        .max(header_end);
    let bytes = source.bytes_at(offset, window_end - offset)?;
    let header = parse_record_header(bytes)?;
    let size = usize::from(header.size);
    if size < 8 {
        return Err(format!(
            "invalid perf record size {size} at offset {offset}"
        ));
    }
    if size > end - offset {
        return Err(format!(
            "perf record overruns data section at offset {offset}"
        ));
    }
    let payload = bytes
        .get(8..size)
        .ok_or_else(|| format!("truncated perf record at offset {offset}"))?;
    Ok(PerfRecord {
        offset,
        header,
        payload,
    })
}

// A queue may retain a window until its timestamp-ordered records are flushed.
struct BufferedScanner<'a> {
    file: &'a File,
    len: usize,
    bytes: Arc<Vec<u8>>,
    current: Option<usize>,
    #[cfg(test)]
    ranges_loaded: usize,
    #[cfg(test)]
    bytes_read: usize,
    #[cfg(test)]
    range_requests: usize,
    #[cfg(test)]
    backing_allocations: usize,
    #[cfg(test)]
    backing_bytes_zeroed: usize,
}

impl BufferedScanner<'_> {
    fn range_start(offset: usize) -> usize {
        offset / SCAN_WINDOW_SIZE * SCAN_WINDOW_SIZE
    }

    fn read_backing(&self, start: usize, size: usize) -> Result<Vec<u8>, String> {
        let mut bytes = vec![0; size];
        #[cfg(unix)]
        self.file
            .read_exact_at(&mut bytes, start as u64)
            .map_err(|error| format!("failed to read perf record backing: {error}"))?;
        #[cfg(not(unix))]
        {
            let mut file = self.file;
            file.seek(SeekFrom::Start(start as u64))
                .map_err(|error| format!("failed to seek perf record backing: {error}"))?;
            file.read_exact(&mut bytes)
                .map_err(|error| format!("failed to read perf record backing: {error}"))?;
        }
        Ok(bytes)
    }

    fn queue_record(
        &mut self,
        offset: usize,
        end: usize,
        header: PerfRecordHeader,
        windows: &mut WindowStore,
    ) -> Result<QueuedPerfRecord, String> {
        let size = usize::from(header.size);
        if size < 8 || offset.checked_add(size).is_none_or(|next| next > end) {
            return Err(format!("invalid queued perf record at offset {offset}"));
        }
        let start = self.current.expect("record_at loads a scanner window");
        if start != Self::range_start(offset) {
            return Err(format!(
                "queued perf record window changed at offset {offset}"
            ));
        }
        let payload_len = size - 8;
        let payload_start = offset - start + 8;
        if payload_start + payload_len > self.bytes.len() {
            return Err(format!("truncated queued perf record at offset {offset}"));
        }
        let window = windows.retain_with(start, || Arc::clone(&self.bytes));
        Ok(QueuedPerfRecord { offset, window })
    }
}

impl RecordSource for BufferedScanner<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        #[cfg(test)]
        {
            self.range_requests += 1;
        }
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= self.len)
            .ok_or_else(|| format!("truncated perf record at offset {offset}"))?;
        let start = Self::range_start(offset);
        if self.current != Some(start) || self.bytes.len() < end - start {
            // Overlap by a maximum-sized record, including split headers.
            let size = (SCAN_WINDOW_SIZE + usize::from(u16::MAX))
                .max(end - start)
                .min(self.len - start);
            #[cfg(test)]
            {
                self.backing_allocations += 1;
                self.backing_bytes_zeroed += size;
            }
            let bytes = self.read_backing(start, size)?;
            self.bytes = Arc::new(bytes);
            self.current = Some(start);
            #[cfg(test)]
            {
                self.ranges_loaded += 1;
                self.bytes_read += size;
            }
        }
        Ok(&self.bytes[offset - start..end - start])
    }
}

/// Sequential file scanning with window-backed ordered delivery.
pub(super) struct FileSource<'a> {
    scanner: BufferedScanner<'a>,
}

impl<'a> FileSource<'a> {
    pub fn new(file: &'a File) -> Result<Self, String> {
        let len = usize::try_from(
            file.metadata()
                .map_err(|error| format!("failed to stat perf.data: {error}"))?
                .len(),
        )
        .map_err(|_| "perf.data size exceeds usize".to_string())?;
        Ok(Self {
            scanner: BufferedScanner {
                file,
                len,
                bytes: Arc::new(Vec::new()),
                current: None,
                #[cfg(test)]
                ranges_loaded: 0,
                #[cfg(test)]
                bytes_read: 0,
                #[cfg(test)]
                range_requests: 0,
                #[cfg(test)]
                backing_allocations: 0,
                #[cfg(test)]
                backing_bytes_zeroed: 0,
            },
        })
    }

    #[cfg(test)]
    fn bytes_read(&self) -> usize {
        self.scanner.bytes_read
    }
}

impl RecordSource for FileSource<'_> {
    fn len(&self) -> usize {
        self.scanner.len()
    }

    fn record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        record_from_window(self, offset, end)
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        self.scanner.bytes_at(offset, len)
    }

    fn queue_record(
        &mut self,
        offset: usize,
        end: usize,
        header: PerfRecordHeader,
        windows: &mut WindowStore,
    ) -> Result<QueuedPerfRecord, String> {
        self.scanner.queue_record(offset, end, header, windows)
    }
}

#[cfg(test)]
mod tests {
    use super::{FileSource, RecordSource, SliceSource, WindowStore};

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(payload.len() + 8);
        bytes.extend(68_u32.to_le_bytes());
        bytes.extend(0_u16.to_le_bytes());
        bytes.extend(u16::try_from(payload.len() + 8).unwrap().to_le_bytes());
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn queued_records_share_a_read_window_and_survive_window_rollover() {
        use std::os::unix::fs::FileExt;

        let window = super::SCAN_WINDOW_SIZE;
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((window * 2 + 64) as u64).unwrap();
        file.as_file().write_all_at(&record(b"first"), 0).unwrap();
        file.as_file()
            .write_all_at(&record(b"same window"), 16)
            .unwrap();
        file.as_file()
            .write_all_at(&record(b"second"), window as u64)
            .unwrap();

        let mut source = FileSource::new(file.as_file()).unwrap();
        let len = source.len();
        let mut windows = WindowStore::default();
        let first_header = source.record_at(0, len).unwrap().header;
        let first = source
            .queue_record(0, len, first_header, &mut windows)
            .unwrap();
        let second_header = source.record_at(16, len).unwrap().header;
        let second_same_window = source
            .queue_record(16, len, second_header, &mut windows)
            .unwrap();
        assert_eq!(first.window, second_same_window.window);
        assert_eq!(windows.record(&first).payload, b"first");
        assert_eq!(windows.record(&second_same_window).payload, b"same window");
        assert_eq!(
            std::sync::Arc::strong_count(&source.scanner.bytes),
            2,
            "one scanner owner plus one queue owner per read window"
        );

        let next_header = source.record_at(window, len).unwrap().header;
        let next_window = source
            .queue_record(window, len, next_header, &mut windows)
            .unwrap();
        assert_ne!(first.window, next_window.window);
        assert_eq!(windows.record(&first).payload, b"first");
        assert_eq!(windows.record(&next_window).payload, b"second");
        assert_eq!(source.scanner.ranges_loaded, 2);
    }

    #[test]
    fn queued_maximum_record_remains_contiguous_across_window_boundary() {
        use std::io::{Seek, SeekFrom, Write};

        let offset = super::SCAN_WINDOW_SIZE - 4;
        let payload = vec![37; usize::from(u16::MAX) - 8];
        let encoded = record(&payload);
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_len((offset + encoded.len() + 32) as u64)
            .unwrap();
        let mut writer = file.as_file();
        writer.seek(SeekFrom::Start(offset as u64)).unwrap();
        writer.write_all(&encoded).unwrap();

        let mut source = FileSource::new(file.as_file()).unwrap();
        let mut windows = WindowStore::default();
        let end = source.len();
        let header = source.record_at(offset, end).unwrap().header;
        let queued = source
            .queue_record(offset, end, header, &mut windows)
            .unwrap();
        assert_eq!(windows.record(&queued).payload, payload);
        assert_eq!(windows.record(&queued).header.size, u16::MAX);
    }

    #[test]
    fn slice_queue_retains_the_complete_header_at_nonzero_offsets() {
        let mut bytes = vec![0; 19];
        let mut encoded = record(b"payload");
        encoded[4..6].copy_from_slice(&37_u16.to_le_bytes());
        bytes.extend(encoded);
        let mut windows = WindowStore::default();
        let mut source = SliceSource(&bytes);
        let end = source.len();
        let expected = source.record_at(19, end).unwrap();
        let expected_header = expected.header;
        let queued = source
            .queue_record(19, end, expected_header, &mut windows)
            .unwrap();
        drop(bytes);
        let retained = windows.record(&queued);
        assert_eq!(retained.offset, 19);
        assert_eq!(retained.header, expected_header);
        assert_eq!(retained.payload, b"payload");
    }

    #[test]
    fn retained_headers_survive_reverse_delivery_and_window_slot_reuse() {
        use std::os::unix::fs::FileExt;

        let size = super::SCAN_WINDOW_SIZE;
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((size * 3 + 64) as u64).unwrap();
        for (offset, payload) in [
            (0, b"first".as_slice()),
            (size, b"second"),
            (size * 2, b"third"),
        ] {
            file.as_file()
                .write_all_at(&record(payload), offset as u64)
                .unwrap();
        }
        let mut source = FileSource::new(file.as_file()).unwrap();
        let end = source.len();
        let mut windows = WindowStore::default();
        let first_header = source.record_at(0, end).unwrap().header;
        let first = source
            .queue_record(0, end, first_header, &mut windows)
            .unwrap();
        let first_backing = std::sync::Arc::downgrade(&source.scanner.bytes);
        let second_header = source.record_at(size, end).unwrap().header;
        let second = source
            .queue_record(size, end, second_header, &mut windows)
            .unwrap();
        assert_eq!(windows.record(&second).payload, b"second");
        assert_eq!(windows.record(&first).payload, b"first");
        windows.release(&first);
        assert!(
            first_backing.upgrade().is_none(),
            "final queued owner releases the old window"
        );
        let third_header = source.record_at(size * 2, end).unwrap().header;
        let third = source
            .queue_record(size * 2, end, third_header, &mut windows)
            .unwrap();
        assert_eq!(third.window, first.window);
        assert_eq!(windows.record(&third).payload, b"third");
        assert_eq!(windows.record(&second).payload, b"second");
        windows.release(&second);
        windows.release(&third);
    }

    #[test]
    fn sequential_scan_reads_each_window_once_and_keeps_storage_bounded() {
        let window = super::SCAN_WINDOW_SIZE;
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((5 * window) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();

        source.bytes_at(0, 8).unwrap();
        let first_read = source.bytes_read();
        source.bytes_at(window - 16, 8).unwrap();
        assert_eq!(source.bytes_read(), first_read);
        source.bytes_at(window, 8).unwrap();
        assert_eq!(
            source.bytes_read(),
            first_read + window + usize::from(u16::MAX)
        );
        assert!(source.scanner.bytes.len() <= window + usize::from(u16::MAX));
    }

    #[test]
    fn failed_window_read_does_not_publish_partial_backing_and_can_retry() {
        let window = super::SCAN_WINDOW_SIZE;
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((2 * window) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        assert_eq!(source.bytes_at(0, 8).unwrap(), [0; 8]);

        file.as_file().set_len((window + 2) as u64).unwrap();
        assert!(source.bytes_at(window, 16).is_err());
        assert_eq!(source.scanner.current, Some(0));
        assert_eq!(source.bytes_at(0, 8).unwrap(), [0; 8]);

        file.as_file().set_len((2 * window) as u64).unwrap();
        assert_eq!(source.bytes_at(window, 8).unwrap(), [0; 8]);
        assert_eq!(source.scanner.current, Some(window));
    }

    #[test]
    fn file_source_reads_by_offset_without_changing_file_cursor() {
        use std::io::{Seek, SeekFrom};

        let mut bytes = record(b"first");
        let far = 128 * 1024;
        bytes.resize(far, 0);
        bytes.extend(record(b"last"));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();

        let mut cursor = file.as_file();
        cursor.seek(SeekFrom::Start(3)).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        assert_eq!(source.record_at(0, bytes.len()).unwrap().payload, b"first");
        assert_eq!(cursor.stream_position().unwrap(), 3);
        assert_eq!(source.record_at(far, bytes.len()).unwrap().payload, b"last");
        assert_eq!(cursor.stream_position().unwrap(), 3);
    }

    #[test]
    fn file_and_slice_sources_apply_identical_record_bounds() {
        let bytes = record(b"payload");
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let mut disk = FileSource::new(file.as_file()).unwrap();
        let mut memory = SliceSource(&bytes);

        for (offset, end) in [
            (0, bytes.len()),
            (0, 4),
            (0, 8),
            (0, usize::MAX),
            (usize::MAX, usize::MAX),
        ] {
            let expected = memory.record_at(offset, end);
            let actual = disk.record_at(offset, end);
            assert_eq!(actual, expected, "offset {offset}, end {end}");
        }
    }
}
