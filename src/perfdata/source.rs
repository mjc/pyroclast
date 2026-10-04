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

    // Called after delivery borrows end. All pending and unscanned records
    // start at or after this offset; retirement must not discard file bytes.
    fn retire_before(&mut self, _offset: usize) -> Result<(), String> {
        Ok(())
    }

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
    // Scan ranges overlap by a maximum u16-sized record; mapped delivery
    // is contiguous throughout. Neither path needs a separate payload copy.
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

// Scanning keeps one reusable, overlapping read buffer. Queued offsets never
// pin it: ordered delivery borrows the original file mapping instead.
struct BufferedScanner<'a> {
    file: &'a File,
    len: usize,
    bytes: Vec<u8>,
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
        offset / DELIVERY_RANGE_SIZE * DELIVERY_RANGE_SIZE
    }

    fn read_backing(&mut self, start: usize) -> Result<(), String> {
        #[cfg(unix)]
        self.file
            .read_exact_at(&mut self.bytes, start as u64)
            .map_err(|error| format!("failed to read perf record backing: {error}"))?;
        #[cfg(not(unix))]
        {
            let mut file = self.file;
            file.seek(SeekFrom::Start(start as u64))
                .map_err(|error| format!("failed to seek perf record backing: {error}"))?;
            file.read_exact(&mut self.bytes)
                .map_err(|error| format!("failed to read perf record backing: {error}"))?;
        }
        Ok(())
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
            let size = (DELIVERY_RANGE_SIZE + usize::from(u16::MAX))
                .max(end - start)
                .min(self.len - start);
            #[cfg(test)]
            {
                self.backing_allocations += usize::from(size > self.bytes.capacity());
                self.backing_bytes_zeroed += size.saturating_sub(self.bytes.len());
            }
            // A failed read may overwrite scratch, but must never publish it.
            self.current = None;
            self.bytes.resize(size, 0);
            self.read_backing(start)?;
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

struct MappedDelivery {
    mapping: Option<memmap2::Mmap>,
    len: usize,
    #[cfg(target_os = "linux")]
    page_size: usize,
    #[cfg(target_os = "linux")]
    retired_until: usize,
    #[cfg(test)]
    range_requests: usize,
}

impl RecordSource for MappedDelivery {
    fn len(&self) -> usize {
        self.len
    }

    fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
        #[cfg(test)]
        {
            self.range_requests += 1;
        }
        let bytes = self.mapping.as_deref().unwrap_or(&[]);
        offset
            .checked_add(len)
            .and_then(|end| bytes.get(offset..end))
            .ok_or_else(|| format!("truncated perf record at offset {offset}"))
    }

    fn record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        record_from_window(self, offset, end)
    }

    fn retire_before(&mut self, offset: usize) -> Result<(), String> {
        if offset > self.len {
            return Err(format!(
                "retirement offset {offset} exceeds perf.data length"
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let end = offset - offset % self.page_size;
            if end > self.retired_until {
                if let Some(mapping) = &self.mapping {
                    // SAFETY: The mapping is read-only, shared original-file
                    // backing, not anonymous/private modified data. No borrowed
                    // record outlives this mutable source call. Both boundaries
                    // are page-aligned and within the mapping. DONTNEED drops
                    // translations, not file bytes; future reads can refault.
                    unsafe {
                        mapping.unchecked_advise_range(
                            memmap2::UncheckedAdvice::DontNeed,
                            self.retired_until,
                            end - self.retired_until,
                        )
                    }
                    .map_err(|error| {
                        format!("failed to retire consumed perf.data pages: {error}")
                    })?;
                }
                self.retired_until = end;
            }
        }
        Ok(())
    }
}

/// Buffered scanning with original-file-backed ordered delivery.
///
/// The input file must remain unchanged (including its length) for the entire
/// source lifetime. Like native perf's read-only `MAP_SHARED` mapping, delivery
/// is not a snapshot and concurrent modification or truncation is unsupported.
pub(super) struct FileSource<'a> {
    scanner: BufferedScanner<'a>,
    delivery: MappedDelivery,
}

impl<'a> FileSource<'a> {
    pub fn new(file: &'a File) -> Result<Self, String> {
        let len = usize::try_from(
            file.metadata()
                .map_err(|error| format!("failed to stat perf.data: {error}"))?
                .len(),
        )
        .map_err(|_| "perf.data size exceeds usize".to_string())?;
        #[cfg(target_os = "linux")]
        // SAFETY: sysconf takes no pointers and queries the running kernel.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|size| *size != 0)
            .ok_or_else(|| "failed to query system page size".to_string())?;
        let mapping = if len == 0 {
            None
        } else {
            // SAFETY: This is a read-only mapping, borrowed only immutably and
            // owned for the entire source lifetime. As with native perf's
            // session.c:reader__mmap (MAP_SHARED, PROT_READ on 64-bit), the
            // input must not be modified or truncated while being processed.
            // This is original-file backing, not a mutation-safe snapshot.
            Some(
                unsafe { memmap2::MmapOptions::new().len(len).map(file) }
                    .map_err(|error| format!("failed to map perf.data: {error}"))?,
            )
        };
        Ok(Self {
            scanner: BufferedScanner {
                file,
                len,
                bytes: Vec::new(),
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
            delivery: MappedDelivery {
                mapping,
                len,
                #[cfg(target_os = "linux")]
                page_size,
                #[cfg(target_os = "linux")]
                retired_until: 0,
                #[cfg(test)]
                range_requests: 0,
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

    fn delivered_record_at(&mut self, offset: usize, end: usize) -> Result<PerfRecord<'_>, String> {
        self.delivery.record_at(offset, end)
    }

    fn retain_record(&mut self, offset: usize) -> Result<(), String> {
        // Retention validates the header extent without faulting mapped pages.
        // The mapping already owns all queued backing; no buffer is pinned.
        offset
            .checked_add(8)
            .filter(|end| *end <= self.delivery.len)
            .map(|_| ())
            .ok_or_else(|| format!("truncated perf record at offset {offset}"))
    }

    fn retire_before(&mut self, offset: usize) -> Result<(), String> {
        self.delivery.retire_before(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::{FileSource, RecordSource, SliceSource};

    #[cfg(target_os = "linux")]
    fn page_is_mapped(address: usize) -> bool {
        use std::os::unix::fs::FileExt;
        // SAFETY: sysconf takes no pointers and queries the running kernel.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let mut entry = [0; 8];
        std::fs::File::open("/proc/self/pagemap")
            .unwrap()
            .read_exact_at(&mut entry, u64::try_from(address / page_size * 8).unwrap())
            .unwrap();
        u64::from_ne_bytes(entry) & (1 << 63) != 0
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retiring_consumed_pages_drops_residency_but_preserves_pending_boundary_pages() {
        let range_size = super::DELIVERY_RANGE_SIZE;
        // SAFETY: sysconf takes no pointers and queries the running kernel.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((3 * range_size) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        let mapping = source.delivery.mapping.as_ref().unwrap();
        let pointer = mapping.as_ptr() as usize;
        for offset in [0, range_size, range_size + page_size] {
            std::hint::black_box(mapping[offset]);
            assert!(page_is_mapped(pointer + offset));
        }

        source.retire_before(range_size + page_size / 2).unwrap();
        assert!(
            !page_is_mapped(pointer),
            "consumed input page remains resident"
        );
        assert!(
            page_is_mapped(pointer + range_size),
            "pending boundary page was retired"
        );
        assert!(page_is_mapped(pointer + range_size + page_size));
        source.retire_before(0).unwrap();
        assert!(page_is_mapped(pointer + range_size));

        source.retire_before(source.len()).unwrap();
        assert!(!page_is_mapped(pointer + range_size));
        assert!(!page_is_mapped(pointer + range_size + page_size));
        // Retirement discards page-table residency, not file bytes or the VMA.
        assert_eq!(source.delivery.bytes_at(0, 8).unwrap(), [0; 8]);
        assert!(page_is_mapped(pointer));
    }

    #[test]
    fn retirement_validates_empty_and_short_files_without_changing_record_bytes() {
        for bytes in [Vec::new(), record(b"short")] {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), &bytes).unwrap();
            let mut source = FileSource::new(file.as_file()).unwrap();
            source.retire_before(0).unwrap();
            assert!(source.retire_before(bytes.len() + 1).is_err());
            assert!(source.retire_before(usize::MAX).is_err());
            source.retire_before(bytes.len()).unwrap();
            assert_eq!(source.delivery.bytes_at(0, bytes.len()).unwrap(), bytes);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retirement_preserves_split_headers_and_maximum_pending_record_payloads() {
        use std::io::{Seek, SeekFrom, Write};
        let file_size = 3 * super::DELIVERY_RANGE_SIZE;
        // SAFETY: sysconf takes no pointers and queries the running kernel.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let offset = super::DELIVERY_RANGE_SIZE + page_size - 4;
        let payload = vec![37; usize::from(u16::MAX) - 8];
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(file_size as u64).unwrap();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.write_all(&record(&payload)).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.record_at(offset, file_size).unwrap();
        source.retain_record(offset).unwrap();
        assert_eq!(
            source
                .delivered_record_at(offset, file_size)
                .unwrap()
                .payload,
            payload
        );
        source.retire_before(offset).unwrap();
        assert_eq!(
            source
                .delivered_record_at(offset, file_size)
                .unwrap()
                .payload,
            payload
        );
        source.release_record(offset);
        source
            .retire_before(offset + usize::from(u16::MAX))
            .unwrap();
        // Even retired records remain accessible through their original file.
        assert_eq!(
            source
                .delivered_record_at(offset, file_size)
                .unwrap()
                .payload,
            payload
        );
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(68_u32.to_le_bytes());
        bytes.extend(0_u16.to_le_bytes());
        bytes.extend(u16::try_from(payload.len() + 8).unwrap().to_le_bytes());
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn queued_records_do_not_retain_private_read_buffers() {
        // A sparse 48 MiB source fixture, not a complete perf recording: twelve
        // queued offsets must not keep twelve private 4 MiB read buffers alive.
        use std::io::{Seek, SeekFrom, Write};
        let range_size = super::DELIVERY_RANGE_SIZE;
        let backing_size = range_size + usize::from(u16::MAX);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((12 * range_size) as u64).unwrap();
        for index in 0..12 {
            file.seek(SeekFrom::Start((index * range_size) as u64))
                .unwrap();
            file.write_all(&record(&[u8::try_from(index).unwrap()]))
                .unwrap();
        }
        let mut source = FileSource::new(file.as_file()).unwrap();
        let mut peak_private_capacity = 0;
        for index in 0..12 {
            let offset = index * range_size;
            assert_eq!(
                source.record_at(offset, source.len()).unwrap().payload,
                [u8::try_from(index).unwrap()]
            );
            source.retain_record(offset).unwrap();
            let private_capacity = source.scanner.bytes.capacity();
            peak_private_capacity = peak_private_capacity.max(private_capacity);
        }
        eprintln!(
            "peak private read-buffer capacity: {peak_private_capacity} bytes; allowance: {backing_size} bytes"
        );
        assert!(
            peak_private_capacity <= backing_size,
            "queued records retained {peak_private_capacity} private read-buffer bytes; scanner needs only {backing_size}"
        );
        for index in (0..12).rev() {
            let offset = index * range_size;
            let mapping_pointer = source.delivery.mapping.as_ref().unwrap()[offset + 8..].as_ptr();
            let delivered = source.delivered_record_at(offset, source.len()).unwrap();
            assert_eq!(delivered.payload, [u8::try_from(index).unwrap()]);
            assert_eq!(delivered.payload.as_ptr(), mapping_pointer);
            source.release_record(offset);
        }
        assert_eq!(source.scanner.backing_allocations, 1);
        assert_eq!(source.scanner.ranges_loaded, 12);
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
            source.scanner.range_requests, 1,
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
        let scan_requests = source.scanner.range_requests;
        let requests = source.delivery.range_requests;
        for _ in 0..512 {
            source.retain_record(0).unwrap();
        }
        assert_eq!(source.delivery.range_requests, requests);
        assert_eq!(source.scanner.range_requests, scan_requests);
        for _ in 0..512 {
            source.release_record(0);
        }
    }

    #[test]
    fn ordered_delivery_borrows_original_mapping_not_private_scan_backing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), record(b"shared")).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        let scanned_record = source.record_at(0, source.len()).unwrap();
        assert_eq!(scanned_record.payload, b"shared");
        let scanned = scanned_record.payload.as_ptr();
        source.retain_record(0).unwrap();
        let mapping_pointer = source.delivery.mapping.as_ref().unwrap()[8..].as_ptr();
        let delivered = source
            .delivered_record_at(0, source.len())
            .unwrap()
            .payload
            .as_ptr();
        assert_ne!(
            scanned, delivered,
            "ordered delivery retained the private scan backing"
        );
        assert_eq!(delivered, mapping_pointer);
        assert_eq!(
            source.delivered_record_at(0, source.len()).unwrap().payload,
            b"shared"
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
        // Every distinct scan range needs a file read, but not a new
        // allocation or another zero-initialization of the reusable buffer.
        let file = tempfile::NamedTempFile::new().unwrap();
        let range_size = super::DELIVERY_RANGE_SIZE;
        let backing_size = range_size + usize::from(u16::MAX);
        file.as_file().set_len((8 * range_size) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        let mut backing_pointer = None;
        for index in 0..6 {
            assert_eq!(source.bytes_at(index * range_size, 8).unwrap(), [0; 8]);
            let actual_pointer = source.scanner.bytes.as_ptr();
            assert_eq!(
                *backing_pointer.get_or_insert(actual_pointer),
                actual_pointer
            );
            assert_eq!(source.scanner.current, Some(index * range_size));
            assert_eq!(source.scanner.bytes.len(), backing_size);
            assert_eq!(source.scanner.ranges_loaded, index + 1);
            assert_eq!(source.bytes_read(), (index + 1) * backing_size);
            assert_eq!(
                (
                    source.scanner.backing_allocations,
                    source.scanner.backing_bytes_zeroed,
                ),
                (1, backing_size),
                "released backing was allocated or zero-initialized again on rollover {index}"
            );
        }
    }

    #[test]
    fn queued_delivery_does_not_pin_or_replace_scanner_backing() {
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
        assert_eq!(
            source.record_at(0, source.len()).unwrap().payload,
            b"pinned"
        );
        let scan_pointer = source.scanner.bytes.as_ptr();
        let pinned_pointer = source.delivery.mapping.as_ref().unwrap()[8..].as_ptr();
        source.retain_record(0).unwrap();
        source.retain_record(0).unwrap();
        assert_eq!(
            source.record_at(range_size, source.len()).unwrap().payload,
            b"scanner"
        );
        let scanner_pointer = source.delivery.mapping.as_ref().unwrap()[range_size + 8..].as_ptr();
        source.retain_record(range_size).unwrap();
        assert_eq!(source.scanner.bytes.as_ptr(), scan_pointer);
        assert_eq!(source.scanner.backing_allocations, 1);
        let before_delivery = source.bytes_read();
        for _ in [1, 0] {
            let delivered = source.delivered_record_at(0, source.len()).unwrap();
            assert_eq!(delivered.payload, b"pinned");
            assert_eq!(delivered.payload.as_ptr(), pinned_pointer);
            source.release_record(0);
            assert_eq!(source.scanner.current, Some(range_size));
            assert_eq!(source.scanner.bytes.as_ptr(), scan_pointer);
        }
        assert_eq!(source.bytes_read(), before_delivery);
        source.bytes_at(2 * range_size, 8).unwrap();
        assert_eq!(
            (
                source.scanner.backing_allocations,
                source.scanner.backing_bytes_zeroed,
            ),
            (1, backing_size),
            "queued delivery allocated or reinitialized scan backing"
        );
        assert_eq!(source.scanner.bytes.as_ptr(), scan_pointer);
        assert_eq!(source.scanner.current, Some(2 * range_size));
        let delivered = source
            .delivered_record_at(range_size, source.len())
            .unwrap();
        assert_eq!(delivered.payload, b"scanner");
        assert_eq!(delivered.payload.as_ptr(), scanner_pointer);
        source.release_record(range_size);
        assert_eq!(source.scanner.current, Some(2 * range_size));
        source.bytes_at(3 * range_size, 8).unwrap();
        assert_eq!(source.scanner.backing_allocations, 1);
        assert_eq!(source.scanner.bytes.as_ptr(), scan_pointer);
        assert_eq!(source.scanner.current, Some(3 * range_size));
    }

    #[test]
    fn retaining_and_releasing_ranges_does_not_allocate_scan_buffers() {
        let range_size = super::DELIVERY_RANGE_SIZE;
        let backing_size = range_size + usize::from(u16::MAX);
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((8 * range_size) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        let mapping_pointer = source.delivery.mapping.as_ref().unwrap().as_ptr();
        for index in 0..6 {
            source.retain_record(index * range_size).unwrap();
            assert_eq!(source.scanner.bytes.capacity(), 0);
            assert_eq!(source.scanner.range_requests, 0);
            assert_eq!(source.delivery.range_requests, 0);
        }
        assert_eq!(source.scanner.backing_allocations, 0);
        for index in (0..6).rev() {
            source.release_record(index * range_size);
            assert_eq!(
                source.delivery.mapping.as_ref().unwrap().as_ptr(),
                mapping_pointer
            );
            assert_eq!(source.scanner.bytes.capacity(), 0);
        }
        assert!(source.scanner.current.is_none());
        assert_eq!(source.bytes_at(6 * range_size, 8).unwrap(), [0; 8]);
        assert_eq!(source.scanner.backing_allocations, 1);
        assert_eq!(source.scanner.backing_bytes_zeroed, backing_size);
        assert_eq!(source.scanner.current, Some(6 * range_size));
        assert_eq!(source.scanner.bytes.len(), backing_size);
    }

    #[test]
    fn scan_buffer_growth_counts_only_newly_initialized_bytes() {
        let range_size = super::DELIVERY_RANGE_SIZE;
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len((5 * range_size) as u64).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.bytes_at(0, 8).unwrap();
        source.bytes_at(range_size, 2 * range_size).unwrap();
        assert_eq!(source.scanner.backing_allocations, 2);
        assert_eq!(source.scanner.backing_bytes_zeroed, 2 * range_size);
        assert_eq!(source.scanner.current, Some(range_size));
        assert_eq!(source.scanner.bytes.len(), 2 * range_size);
        source.bytes_at(2 * range_size, 8).unwrap();
        assert_eq!(source.scanner.backing_allocations, 2);
        assert_eq!(source.scanner.backing_bytes_zeroed, 2 * range_size);
        assert_eq!(source.scanner.current, Some(2 * range_size));
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
            assert_eq!(
                source.scanner.current,
                Some(super::BufferedScanner::range_start(offset))
            );
        }
        assert!(source.bytes_at(tail + 8, usize::from(u16::MAX)).is_err());
        assert_eq!(
            source.record_at(boundary, source.len()).unwrap().payload,
            &large[8..]
        );
    }

    #[test]
    fn failed_scan_read_preserves_mapped_records_and_retry_payloads() {
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
        let error = source.bytes_at(2 * range_size, 8).unwrap_err();
        assert!(error.starts_with("failed to read perf record backing:"));
        assert!(source.scanner.current.is_none());
        assert_eq!(source.scanner.ranges_loaded, 2);
        // Inject an error only into the buffered read, then restore the file
        // extent before accessing any mapped delivery pages.
        file.as_file().set_len((4 * range_size) as u64).unwrap();
        assert_eq!(
            source.delivered_record_at(0, source.len()).unwrap().payload,
            b"retained"
        );
        source.release_record(0);
        assert!(source.scanner.current.is_none());
        assert_eq!(
            source
                .record_at(2 * range_size, source.len())
                .unwrap()
                .payload,
            b"retry"
        );
        assert_eq!(source.scanner.current, Some(2 * range_size));
        assert_eq!(source.scanner.ranges_loaded, 3);
        assert_eq!(
            source
                .delivered_record_at(2 * range_size, source.len())
                .unwrap()
                .payload,
            b"retry"
        );
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
            source.scanner.ranges_loaded, 1,
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
        assert_eq!(
            disk.scanner.current,
            Some(super::BufferedScanner::range_start(second))
        );
    }

    #[test]
    fn file_source_private_storage_is_independent_of_recording_size() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        for offset in [0, 32 * 1024 * 1024, source.len() - 8, 0] {
            assert_eq!(source.bytes_at(offset, 8).unwrap(), [0; 8]);
            assert_eq!(
                source.scanner.current,
                Some(super::BufferedScanner::range_start(offset))
            );
            assert!(
                source.scanner.bytes.len() <= super::DELIVERY_RANGE_SIZE + usize::from(u16::MAX)
            );
            assert!(
                source.scanner.bytes.capacity()
                    <= super::DELIVERY_RANGE_SIZE + usize::from(u16::MAX)
            );
            assert_eq!(
                source.delivery.mapping.as_ref().unwrap().len(),
                source.len()
            );
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
        assert_eq!(source.scanner.ranges_loaded, 2);
        assert_eq!(source.scanner.backing_allocations, 1);
        assert_eq!(source.scanner.current, Some(far));
    }

    #[test]
    fn queued_offsets_remain_deliverable_without_private_range_retention() {
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
        let mapping_pointer = source.delivery.mapping.as_ref().unwrap().as_ptr();
        assert_eq!(source.scanner.bytes.capacity(), 0);
        for offset in [offsets[2], 0, offsets[1], 0] {
            assert_eq!(
                source
                    .delivered_record_at(offset, source.len())
                    .unwrap()
                    .payload,
                b"pending"
            );
            source.release_record(offset);
            assert_eq!(source.scanner.bytes.capacity(), 0);
            assert_eq!(
                source.delivery.mapping.as_ref().unwrap().as_ptr(),
                mapping_pointer
            );
        }
        assert_eq!(source.scanner.ranges_loaded, 0);
        assert!(source.scanner.current.is_none());
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
        assert_eq!(source.scanner.ranges_loaded, 2);
        assert_eq!(
            source.scanner.current,
            Some(super::BufferedScanner::range_start(second))
        );
    }

    #[test]
    fn invalid_mapped_delivery_ranges_do_not_corrupt_pending_backing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), record(b"retained")).unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        source.retain_record(0).unwrap();
        let mapping_pointer = source.delivery.mapping.as_ref().unwrap().as_ptr();
        let requests = source.delivery.range_requests;
        assert!(source.retain_record(usize::MAX).is_err());
        assert!(source.retain_record(source.len() - 4).is_err());
        assert_eq!(source.delivery.range_requests, requests);
        assert_eq!(source.scanner.range_requests, 0);
        assert!(source.delivery.bytes_at(usize::MAX, 8).is_err());
        assert!(source.delivery.bytes_at(source.len() - 4, 8).is_err());
        assert!(source.delivered_record_at(0, 8).is_err());
        assert_eq!(
            source.delivery.mapping.as_ref().unwrap().as_ptr(),
            mapping_pointer
        );
        assert_eq!(
            source.delivered_record_at(0, source.len()).unwrap().payload,
            b"retained"
        );
        source.release_record(0);
        assert_eq!(source.scanner.bytes.capacity(), 0);
        assert_eq!(
            source.delivery.mapping.as_ref().unwrap().as_ptr(),
            mapping_pointer
        );
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
        assert!(source.scanner.current.is_none());
        assert_eq!(source.scanner.ranges_loaded, 1);
        file.as_file()
            .set_len((2 * super::DELIVERY_RANGE_SIZE) as u64)
            .unwrap();
        assert_eq!(
            source.bytes_at(super::DELIVERY_RANGE_SIZE, 16).unwrap(),
            [0; 16]
        );
        assert_eq!(source.scanner.current, Some(super::DELIVERY_RANGE_SIZE));
        assert_eq!(source.bytes_at(0, 2).unwrap(), b"ab");
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
                let delivered = disk.delivered_record_at(offset, end);
                assert_eq!(
                    delivered, expected,
                    "delivery offset {offset}, end {end}, {bytes:?}"
                );
            }
        }
    }

    #[test]
    fn file_source_reports_truncated_ranges_without_overflow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut source = FileSource::new(file.as_file()).unwrap();
        assert!(source.bytes_at(0, 8).is_err());
        assert!(source.bytes_at(usize::MAX, 8).is_err());
        assert!(source.delivery.mapping.is_none());
        assert!(source.retain_record(0).is_err());
        assert!(source.retain_record(usize::MAX).is_err());
        assert!(source.delivered_record_at(0, 0).is_err());
        assert!(source.delivery.bytes_at(usize::MAX, 8).is_err());
        assert!(source.delivery.bytes_at(0, 0).unwrap().is_empty());
    }
}
