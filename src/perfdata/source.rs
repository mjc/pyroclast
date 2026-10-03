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

const DELIVERY_RANGE_SIZE: usize = 4 * 1024 * 1024;

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
    // Delivery ranges already overlap by a maximum u16-sized record, so
    // borrowing this window neither reads again nor copies the payload.
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

struct QueuedRange {
    bytes: Vec<u8>,
    pending: usize,
}

// session.c:reader__mmap and ordered-events.c:dup_event/do_flush keep backing
// alive through ordered delivery. Read each range once and borrow it for both
// scanning and delivery, avoiding a second filesystem path and mmap faults.
struct BufferedDelivery<'a> {
    file: &'a File,
    len: usize,
    ranges: BTreeMap<usize, QueuedRange>,
    // Refill scratch owns one released allocation, never queued records.
    refill_buffer: Option<Vec<u8>>,
    current: Option<usize>,
    scan_current: Option<usize>,
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

impl BufferedDelivery<'_> {
    fn range_start(offset: usize) -> usize {
        offset / DELIVERY_RANGE_SIZE * DELIVERY_RANGE_SIZE
    }

    fn recycle_range(&mut self, start: usize) {
        if let Some(range) = self.ranges.remove(&start) {
            debug_assert_eq!(range.pending, 0);
            debug_assert_ne!(self.scan_current, Some(start));
            self.refill_buffer = Some(range.bytes);
        }
    }

    fn read_backing(&mut self, bytes: &mut [u8], start: usize) -> Result<(), String> {
        #[cfg(unix)]
        self.file
            .read_exact_at(bytes, start as u64)
            .map_err(|error| format!("failed to read perf record backing: {error}"))?;
        #[cfg(not(unix))]
        {
            self.file
                .seek(SeekFrom::Start(start as u64))
                .map_err(|error| format!("failed to seek perf record backing: {error}"))?;
            self.file
                .read_exact(bytes)
                .map_err(|error| format!("failed to read perf record backing: {error}"))?;
        }
        Ok(())
    }
}

impl RecordSource for BufferedDelivery<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        record_from_window(self, offset, end)
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
            let mut bytes = self.refill_buffer.take().unwrap_or_default();
            #[cfg(test)]
            {
                self.backing_allocations += usize::from(size > bytes.capacity());
                self.backing_bytes_zeroed += size.saturating_sub(bytes.len());
            }
            bytes.resize(size, 0);
            if let Err(error) = self.read_backing(&mut bytes, start) {
                self.refill_buffer = Some(bytes);
                return Err(error);
            }
            let pending = self.ranges.get(&start).map_or(0, |range| range.pending);
            self.ranges.insert(start, QueuedRange { bytes, pending });
            #[cfg(test)]
            {
                self.ranges_loaded += 1;
                self.bytes_read += size;
            }
        }
        if let Some(previous) = self.current.replace(start).filter(|old| *old != start)
            && self.scan_current != Some(previous)
            && self
                .ranges
                .get(&previous)
                .is_some_and(|range| range.pending == 0)
        {
            self.recycle_range(previous);
        }
        Ok(&self.ranges[&start].bytes[offset - start..end - start])
    }

    fn retain_record(&mut self, offset: usize) -> Result<(), String> {
        let start = Self::range_start(offset);
        if let Some(range) = self.ranges.get_mut(&start)
            && offset - start <= range.bytes.len().saturating_sub(8)
            && range.bytes.len() >= 8
        {
            range.pending += 1;
            return Ok(());
        }
        self.bytes_at(offset, 8)?;
        self.ranges
            .get_mut(&start)
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
        debug_assert!(
            range.pending > 0,
            "released record must have a matching retain"
        );
        range.pending -= 1;
        if range.pending == 0 && self.scan_current != Some(start) {
            self.recycle_range(start);
            if self.current == Some(start) {
                self.current = None;
            }
        }
    }
}

pub(super) struct FileSource<'a> {
    delivery: BufferedDelivery<'a>,
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
            delivery: BufferedDelivery {
                file,
                len,
                ranges: BTreeMap::new(),
                refill_buffer: None,
                current: None,
                scan_current: None,
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
        self.delivery.bytes_read
    }
}

impl RecordSource for FileSource<'_> {
    fn len(&self) -> usize {
        self.delivery.len()
    }

    fn record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        record_from_window(self, offset, end)
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        // Only scanning pins a range between finished rounds. Ordered
        // delivery of another range must not evict the scanner's backing.
        if let Some(previous) = self
            .delivery
            .scan_current
            .replace(BufferedDelivery::range_start(offset))
            .filter(|old| *old != BufferedDelivery::range_start(offset))
            && self
                .delivery
                .ranges
                .get(&previous)
                .is_some_and(|range| range.pending == 0)
        {
            self.delivery.recycle_range(previous);
        }
        self.delivery.bytes_at(offset, len)
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
    fn scanning_records_acquires_one_contiguous_window() {
        // perf session.c:prefetch_event (2180) validates the header and payload
        // in the same backing; reader__read_event (2387) advances by its size.
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes = record(b"shared");
        std::fs::write(file.path(), &bytes).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.record_at(0, bytes.len()).unwrap();
        assert_eq!(
            source.delivery.range_requests, 1,
            "scanner repeats backing lookup"
        );
    }

    #[test]
    fn delivering_records_acquires_one_contiguous_window() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes = record(b"shared");
        std::fs::write(file.path(), &bytes).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.retain_record(0).unwrap();
        let requests = source.delivery.range_requests;
        source.delivered_record_at(0, bytes.len()).unwrap();
        assert_eq!(
            source.delivery.range_requests - requests,
            1,
            "delivery repeats backing lookup"
        );
        source.release_record(0);
    }

    #[test]
    fn retaining_scanned_records_does_not_reacquire_their_backing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes = record(b"shared");
        std::fs::write(file.path(), &bytes).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.record_at(0, bytes.len()).unwrap();
        let requests = source.delivery.range_requests;
        for _ in 0..512 {
            source.retain_record(0).unwrap();
        }
        assert_eq!(source.delivery.range_requests, requests);
        for _ in 0..512 {
            source.release_record(0);
        }
    }

    #[test]
    fn scan_and_ordered_delivery_borrow_the_same_record_backing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), record(b"shared")).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        let scanned = source.record_at(0, source.len()).unwrap().payload.as_ptr();
        source.retain_record(0).unwrap();
        let delivered = source
            .delivered_record_at(0, source.len())
            .unwrap()
            .payload
            .as_ptr();
        assert_eq!(
            scanned, delivered,
            "ordered delivery duplicated the scan backing"
        );
        source.release_record(0);
    }

    #[test]
    fn scanning_a_delivery_range_reads_its_backing_once() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_len((super::DELIVERY_RANGE_SIZE * 2) as u64)
            .unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.bytes_at(0, 8).unwrap();
        let initial_read = source.bytes_read();
        source.bytes_at(3 * 1024 * 1024, 8).unwrap();
        assert_eq!(
            source.bytes_read(),
            initial_read,
            "small scan windows reread the same delivery range"
        );
    }

    #[test]
    fn sequential_range_rollover_reuses_one_initialized_backing() {
        // perf session.c:reader__mmap releases the replaced backing before
        // mapping the next window. This tests allocation, not fewer reads:
        // every distinct input range still needs its own complete file read.
        let file = tempfile::NamedTempFile::new().unwrap();
        let range_size = super::DELIVERY_RANGE_SIZE;
        let backing_size = range_size + usize::from(u16::MAX);
        file.as_file().set_len((8 * range_size) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        let mut backing_pointer = None;
        for index in 0..6 {
            assert_eq!(source.bytes_at(index * range_size, 8).unwrap(), [0; 8]);
            let actual_pointer = source.delivery.ranges[&(index * range_size)].bytes.as_ptr();
            assert_eq!(
                *backing_pointer.get_or_insert(actual_pointer),
                actual_pointer
            );
            assert_eq!(source.delivery.ranges.len(), 1);
            assert!(source.delivery.refill_buffer.is_none());
            assert_eq!(source.delivery.ranges_loaded, index + 1);
            assert_eq!(source.bytes_read(), (index + 1) * backing_size);
            assert_eq!(
                (
                    source.delivery.backing_allocations,
                    source.delivery.backing_bytes_zeroed,
                ),
                (1, backing_size),
                "released backing was allocated or zero-initialized again on rollover {index}"
            );
        }
    }

    #[test]
    fn last_queued_delivery_recycles_only_unpinned_backing_for_the_scanner() {
        use std::io::{Seek, SeekFrom, Write};
        let range_size = super::DELIVERY_RANGE_SIZE;
        let backing_size = range_size + usize::from(u16::MAX);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((5 * range_size) as u64).unwrap();
        for (offset, payload) in [(0, &b"pinned"[..]), (range_size, &b"scanner"[..])] {
            file.seek(SeekFrom::Start(offset as u64)).unwrap();
            file.write_all(&record(payload)).unwrap();
        }
        let mut source = FileSource::new(file.as_file()).unwrap();
        let pinned_pointer = source.record_at(0, source.len()).unwrap().payload.as_ptr();
        source.retain_record(0).unwrap();
        source.retain_record(0).unwrap();
        let scanner_pointer = source
            .record_at(range_size, source.len())
            .unwrap()
            .payload
            .as_ptr();
        source.retain_record(range_size).unwrap();
        assert_eq!(source.delivery.backing_allocations, 2);
        let before_delivery = source.bytes_read();
        for remaining in [1, 0] {
            let delivered = source.delivered_record_at(0, source.len()).unwrap();
            assert_eq!(delivered.payload, b"pinned");
            assert_eq!(delivered.payload.as_ptr(), pinned_pointer);
            source.release_record(0);
            assert_eq!(source.delivery.ranges.contains_key(&0), remaining != 0);
            assert_eq!(source.delivery.refill_buffer.is_some(), remaining == 0);
        }
        assert_eq!(source.bytes_read(), before_delivery);
        source.bytes_at(2 * range_size, 8).unwrap();
        assert_eq!(
            (
                source.delivery.backing_allocations,
                source.delivery.backing_bytes_zeroed,
            ),
            (2, 2 * backing_size),
            "last delivery discarded backing instead of reusing it for the scanner"
        );
        assert_eq!(source.delivery.ranges.len(), 2);
        assert!(source.delivery.refill_buffer.is_none());
        let delivered = source
            .delivered_record_at(range_size, source.len())
            .unwrap();
        assert_eq!(delivered.payload, b"scanner");
        assert_eq!(delivered.payload.as_ptr(), scanner_pointer);
        source.release_record(range_size);
        assert_eq!(source.delivery.ranges.len(), 1);
        source.bytes_at(3 * range_size, 8).unwrap();
        assert_eq!(source.delivery.backing_allocations, 2);
        assert_eq!(source.delivery.ranges.len(), 1);
    }

    #[test]
    fn released_ranges_leave_only_one_refill_allocation() {
        let range_size = super::DELIVERY_RANGE_SIZE;
        let backing_size = range_size + usize::from(u16::MAX);
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((8 * range_size) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for index in 0..6 {
            source.retain_record(index * range_size).unwrap();
            assert_eq!(source.delivery.ranges.len(), index + 1);
            assert!(source.delivery.refill_buffer.is_none());
        }
        assert_eq!(source.delivery.backing_allocations, 6);
        for index in (0..6).rev() {
            let offset = index * range_size;
            let released_pointer = source.delivery.ranges[&offset].bytes.as_ptr();
            source.release_record(offset);
            assert_eq!(source.delivery.ranges.len(), index);
            let scratch = source.delivery.refill_buffer.as_ref().unwrap();
            assert_eq!(scratch.as_ptr(), released_pointer);
            assert_eq!(scratch.len(), backing_size);
            assert!(
                source
                    .delivery
                    .ranges
                    .values()
                    .all(|range| range.pending == 1)
            );
        }
        assert!(source.delivery.current.is_none());
        source.bytes_at(6 * range_size, 8).unwrap();
        assert_eq!(source.delivery.backing_allocations, 6);
        assert_eq!(source.delivery.backing_bytes_zeroed, 6 * backing_size);
        assert_eq!(source.delivery.ranges.len(), 1);
        assert!(source.delivery.refill_buffer.is_none());
    }

    #[test]
    fn refill_buffer_growth_counts_only_newly_initialized_bytes() {
        let range_size = super::DELIVERY_RANGE_SIZE;
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((5 * range_size) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.bytes_at(0, 8).unwrap();
        source.bytes_at(range_size, 2 * range_size).unwrap();
        assert_eq!(source.delivery.backing_allocations, 2);
        assert_eq!(source.delivery.backing_bytes_zeroed, 2 * range_size);
        assert_eq!(source.delivery.ranges.len(), 1);
        source.bytes_at(2 * range_size, 8).unwrap();
        assert_eq!(source.delivery.backing_allocations, 2);
        assert_eq!(source.delivery.backing_bytes_zeroed, 2 * range_size);
        assert_eq!(source.delivery.ranges.len(), 1);
    }

    #[test]
    fn recycled_backing_preserves_short_tail_and_backward_boundary_records() {
        use std::io::{Seek, SeekFrom, Write};
        let range_size = super::DELIVERY_RANGE_SIZE;
        let boundary = range_size - 4;
        let large = record(&vec![7; usize::from(u16::MAX) - 8]);
        let tail = 2 * range_size;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.seek(SeekFrom::Start(boundary as u64)).unwrap();
        file.write_all(&large).unwrap();
        file.seek(SeekFrom::Start(tail as u64)).unwrap();
        file.write_all(&record(b"short tail")).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for (offset, expected) in [
            (boundary, &large[8..]),
            (tail, &b"short tail"[..]),
            (boundary, &large[8..]),
            (tail, &b"short tail"[..]),
        ] {
            assert_eq!(
                source.record_at(offset, source.len()).unwrap().payload,
                expected
            );
            assert_eq!(source.delivery.ranges.len(), 1);
        }
        assert!(source.bytes_at(tail + 8, usize::from(u16::MAX)).is_err());
        assert_eq!(
            source.record_at(boundary, source.len()).unwrap().payload,
            &large[8..]
        );
    }

    #[test]
    fn failed_recycled_read_preserves_pinned_records_and_retry_payloads() {
        use std::io::{Seek, SeekFrom, Write};
        let range_size = super::DELIVERY_RANGE_SIZE;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((4 * range_size) as u64).unwrap();
        for (offset, payload) in [(0, &b"retained"[..]), (2 * range_size, &b"retry"[..])] {
            file.seek(SeekFrom::Start(offset as u64)).unwrap();
            file.write_all(&record(payload)).unwrap();
        }
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.record_at(0, source.len()).unwrap();
        source.retain_record(0).unwrap();
        source.bytes_at(range_size, 8).unwrap();
        file.as_file()
            .set_len((2 * range_size + 16) as u64)
            .unwrap();
        assert!(source.bytes_at(2 * range_size, 8).is_err());
        assert!(!source.delivery.ranges.contains_key(&(2 * range_size)));
        assert_eq!(source.delivery.ranges.len(), 1);
        assert_eq!(
            source.delivered_record_at(0, source.len()).unwrap().payload,
            b"retained"
        );
        source.release_record(0);
        assert!(source.delivery.ranges.is_empty());
        file.as_file().set_len((4 * range_size) as u64).unwrap();
        assert_eq!(
            source
                .record_at(2 * range_size, source.len())
                .unwrap()
                .payload,
            b"retry"
        );
        assert_eq!(source.delivery.ranges.len(), 1);
    }

    #[test]
    fn finished_round_delivery_keeps_the_still_active_scan_range() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = record(b"first");
        let next = bytes.len();
        bytes.extend(record(b"next"));
        std::fs::write(file.path(), bytes).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for offset in [0, next] {
            source.record_at(offset, source.len()).unwrap();
            source.retain_record(offset).unwrap();
            source.delivered_record_at(offset, source.len()).unwrap();
            source.release_record(offset);
        }
        assert_eq!(
            source.delivery.ranges_loaded, 1,
            "round flushing recreated active backing"
        );
    }

    #[test]
    fn slice_and_file_sources_match_across_window_edges_and_backward_delivery() {
        let mut bytes = vec![0; super::DELIVERY_RANGE_SIZE - 4];
        let first = bytes.len();
        bytes.extend(record(&vec![1; 65527]));
        let second = bytes.len();
        bytes.extend(record(b"second"));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let mut disk = FileSource::new(file.as_file()).unwrap();
        // The first header straddles a range boundary.
        disk.bytes_at(0, 8).unwrap();
        let mut memory = SliceSource(&bytes);
        for offset in [first, second, first, second] {
            let expected = memory.record_at(offset, bytes.len()).unwrap();
            let actual = disk.record_at(offset, bytes.len()).unwrap();
            assert_eq!(actual.offset, expected.offset);
            assert_eq!(actual.header, expected.header);
            assert_eq!(actual.payload, expected.payload);
        }
        assert_eq!(disk.delivery.ranges.len(), 1);
    }

    #[test]
    fn file_source_storage_is_independent_of_recording_size() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for offset in [0, 32 * 1024 * 1024, source.len() - 8, 0] {
            assert_eq!(source.bytes_at(offset, 8).unwrap(), [0; 8]);
            assert_eq!(source.delivery.ranges.len(), 1);
            assert!(source.delivery.ranges.values().all(
                |range| range.bytes.len() <= super::DELIVERY_RANGE_SIZE + usize::from(u16::MAX)
            ));
        }
    }

    #[test]
    fn retained_ordered_delivery_does_not_reread_sequential_backing() {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let bytes = record(b"");
        file.write_all(&bytes).unwrap();
        let far = 32 * 1024 * 1024;
        file.seek(SeekFrom::Start(far as u64)).unwrap();
        file.write_all(&bytes).unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for offset in [0, far] {
            source.record_at(offset, source.len()).unwrap();
            for _ in 0..16 {
                source.retain_record(offset).unwrap();
            }
        }
        let before_delivery = source.bytes_read();
        for _ in 0..16 {
            for offset in [far, 0] {
                source.delivered_record_at(offset, source.len()).unwrap();
                source.release_record(offset);
            }
        }
        assert_eq!(source.bytes_read(), before_delivery);
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
        assert_eq!(source.delivery.ranges_loaded, 2);
        assert!(
            source
                .delivery
                .ranges
                .values()
                .all(|range| range.pending == 0)
        );
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
        assert_eq!(source.delivery.ranges_loaded, 3);
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
        assert_eq!(source.delivery.ranges_loaded, 2);
        assert!(
            source
                .delivery
                .ranges
                .values()
                .all(|range| range.pending == 0)
        );
    }

    #[test]
    fn invalid_buffered_delivery_ranges_do_not_corrupt_pending_backing() {
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
    fn failed_range_read_does_not_publish_partially_read_backing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"ab").unwrap();
        file.as_file()
            .set_len((2 * super::DELIVERY_RANGE_SIZE) as u64)
            .unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        assert_eq!(source.bytes_at(0, 2).unwrap(), b"ab");
        file.as_file()
            .set_len((super::DELIVERY_RANGE_SIZE + 2) as u64)
            .unwrap();
        assert!(source.bytes_at(super::DELIVERY_RANGE_SIZE, 16).is_err());
        assert!(
            !source
                .delivery
                .ranges
                .contains_key(&super::DELIVERY_RANGE_SIZE)
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
    fn buffered_record_windows_preserve_slice_validation_and_payloads() {
        let valid = record(b"payload");
        let mut short_header = valid.clone();
        short_header.truncate(4);
        let mut bad_size = valid.clone();
        bad_size[6..8].copy_from_slice(&4_u16.to_le_bytes());
        let mut short_payload = valid.clone();
        short_payload.truncate(10);
        for bytes in [&valid, &short_header, &bad_size, &short_payload] {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), bytes).unwrap();
            let mut memory = SliceSource(bytes);
            let mut disk = FileSource::new(file.as_file()).unwrap();
            for (offset, end) in [
                (0, bytes.len()),
                (0, 4),
                (0, 8),
                (0, valid.len()),
                (0, usize::MAX),
                (usize::MAX, usize::MAX),
            ] {
                let expected = memory.record_at(offset, end);
                let actual = disk.record_at(offset, end);
                assert_eq!(actual, expected, "offset {offset}, end {end}, {bytes:?}");
            }
        }
    }

    #[test]
    fn file_source_reports_truncated_ranges_without_overflow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        assert!(source.bytes_at(0, 8).is_err());
        assert!(source.bytes_at(usize::MAX, 8).is_err());
    }
}
