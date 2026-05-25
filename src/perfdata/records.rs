use crate::perfdata::endian::{read_u16, read_u32, read_u64};
use crate::perfdata::header::PerfHeader;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfRecordHeader {
    pub record_type: u32,
    pub misc: u16,
    pub size: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfRecord<'a> {
    pub offset: usize,
    pub header: PerfRecordHeader,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommRecord {
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmapRecord {
    pub pid: u32,
    pub tid: u32,
    pub start: u64,
    pub len: u64,
    pub pgoff: u64,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mmap2Record {
    pub pid: u32,
    pub tid: u32,
    pub start: u64,
    pub len: u64,
    pub pgoff: u64,
    pub major: u32,
    pub minor: u32,
    pub inode: u64,
    pub inode_generation: u64,
    pub prot: u32,
    pub flags: u32,
    pub path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkRecord {
    pub pid: u32,
    pub ppid: u32,
    pub tid: u32,
    pub ptid: u32,
    pub time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitRecord {
    pub pid: u32,
    pub ppid: u32,
    pub tid: u32,
    pub ptid: u32,
    pub time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LostRecord {
    pub id: u64,
    pub lost: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LostSamplesRecord {
    pub lost: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessLifecycleRecord {
    pid: u32,
    ppid: u32,
    tid: u32,
    ptid: u32,
    time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmapRange {
    pid: u32,
    tid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
}

/// Parses a perf record header.
///
/// # Errors
///
/// Returns an error when fewer than eight bytes are available.
pub fn parse_record_header(bytes: &[u8]) -> Result<PerfRecordHeader, String> {
    if bytes.len() < 8 {
        return Err("perf record header is shorter than 8 bytes".to_string());
    }

    Ok(PerfRecordHeader {
        record_type: read_u32(bytes, 0)?,
        misc: read_u16(bytes, 4)?,
        size: read_u16(bytes, 6)?,
    })
}

/// Iterates over records in the perf data section.
///
/// # Errors
///
/// Returns an error when the data section offsets are invalid or a contained
/// record is truncated.
pub fn iter_records(bytes: &[u8], header: PerfHeader) -> Result<Vec<PerfRecord<'_>>, String> {
    let mut records = Vec::new();
    let mut offset = to_usize(header.data_offset, "perf data section offset")?;
    let data_size = to_usize(header.data_size, "perf data section size")?;
    let end = offset
        .checked_add(data_size)
        .ok_or_else(|| "perf data section size overflows usize".to_string())?;

    if end > bytes.len() {
        return Err("perf data section extends past end of file".to_string());
    }

    while offset < end {
        let record_header = parse_record_header(
            bytes
                .get(offset..offset + 8)
                .ok_or_else(|| format!("truncated perf record header at offset {offset}"))?,
        )?;
        let size = record_header.size as usize;
        if size < 8 {
            return Err(format!(
                "invalid perf record size {size} at offset {offset}"
            ));
        }
        let next = offset
            .checked_add(size)
            .ok_or_else(|| format!("perf record size overflows at offset {offset}"))?;
        if next > end {
            return Err(format!(
                "perf record overruns data section at offset {offset}"
            ));
        }
        records.push(PerfRecord {
            offset,
            header: record_header,
            payload: &bytes[offset + 8..next],
        });
        offset = next;
    }

    Ok(records)
}

/// Parses a `PERF_RECORD_COMM` payload.
///
/// # Errors
///
/// Returns an error when the fixed pid/tid fields are missing.
pub fn parse_comm_record(payload: &[u8]) -> Result<CommRecord, String> {
    if payload.len() < 8 {
        return Err("PERF_RECORD_COMM payload is shorter than 8 bytes".to_string());
    }
    let pid = read_u32(payload, 0)?;
    let tid = read_u32(payload, 4)?;
    let comm = parse_c_string(&payload[8..]);

    Ok(CommRecord { pid, tid, comm })
}

/// Parses a `PERF_RECORD_MMAP` payload.
///
/// # Errors
///
/// Returns an error when the fixed mapping fields are missing.
pub fn parse_mmap_record(payload: &[u8]) -> Result<MmapRecord, String> {
    if payload.len() < 32 {
        return Err("PERF_RECORD_MMAP payload is shorter than 32 bytes".to_string());
    }
    let range = parse_mmap_range(payload)?;
    let path = parse_c_string(&payload[32..]);

    Ok(MmapRecord {
        pid: range.pid,
        tid: range.tid,
        start: range.start,
        len: range.len,
        pgoff: range.pgoff,
        path,
    })
}

/// Parses a `PERF_RECORD_MMAP2` payload.
///
/// # Errors
///
/// Returns an error when the fixed mapping and inode fields are missing.
pub fn parse_mmap2_record(payload: &[u8]) -> Result<Mmap2Record, String> {
    if payload.len() < 64 {
        return Err("PERF_RECORD_MMAP2 payload is shorter than 64 bytes".to_string());
    }
    let range = parse_mmap_range(payload)?;
    let major = read_u32(payload, 32)?;
    let minor = read_u32(payload, 36)?;
    let inode = read_u64(payload, 40)?;
    let inode_generation = read_u64(payload, 48)?;
    let prot = read_u32(payload, 56)?;
    let flags = read_u32(payload, 60)?;
    let path = parse_c_string(&payload[64..]);

    Ok(Mmap2Record {
        pid: range.pid,
        tid: range.tid,
        start: range.start,
        len: range.len,
        pgoff: range.pgoff,
        major,
        minor,
        inode,
        inode_generation,
        prot,
        flags,
        path,
    })
}

/// Parses a `PERF_RECORD_FORK` payload.
///
/// # Errors
///
/// Returns an error when the fixed process/thread fields are missing.
pub fn parse_fork_record(payload: &[u8]) -> Result<ForkRecord, String> {
    let record = parse_process_lifecycle_record(payload, "PERF_RECORD_FORK")?;

    Ok(ForkRecord::from(record))
}

/// Parses a `PERF_RECORD_EXIT` payload.
///
/// # Errors
///
/// Returns an error when the fixed process/thread fields are missing.
pub fn parse_exit_record(payload: &[u8]) -> Result<ExitRecord, String> {
    let record = parse_process_lifecycle_record(payload, "PERF_RECORD_EXIT")?;

    Ok(ExitRecord::from(record))
}

/// Parses a `PERF_RECORD_LOST` payload.
///
/// # Errors
///
/// Returns an error when the fixed id/lost fields are missing.
pub fn parse_lost_record(payload: &[u8]) -> Result<LostRecord, String> {
    if payload.len() < 16 {
        return Err("PERF_RECORD_LOST payload is shorter than 16 bytes".to_string());
    }

    Ok(LostRecord {
        id: read_u64(payload, 0)?,
        lost: read_u64(payload, 8)?,
    })
}

/// Parses a `PERF_RECORD_LOST_SAMPLES` payload.
///
/// # Errors
///
/// Returns an error when the fixed lost field is missing.
pub fn parse_lost_samples_record(payload: &[u8]) -> Result<LostSamplesRecord, String> {
    if payload.len() < 8 {
        return Err("PERF_RECORD_LOST_SAMPLES payload is shorter than 8 bytes".to_string());
    }

    Ok(LostSamplesRecord {
        lost: read_u64(payload, 0)?,
    })
}

fn parse_process_lifecycle_record(
    payload: &[u8],
    record_name: &str,
) -> Result<ProcessLifecycleRecord, String> {
    if payload.len() < 24 {
        return Err(format!("{record_name} payload is shorter than 24 bytes"));
    }

    Ok(ProcessLifecycleRecord {
        pid: read_u32(payload, 0)?,
        ppid: read_u32(payload, 4)?,
        tid: read_u32(payload, 8)?,
        ptid: read_u32(payload, 12)?,
        time: read_u64(payload, 16)?,
    })
}

impl From<ProcessLifecycleRecord> for ForkRecord {
    fn from(record: ProcessLifecycleRecord) -> Self {
        Self {
            pid: record.pid,
            ppid: record.ppid,
            tid: record.tid,
            ptid: record.ptid,
            time: record.time,
        }
    }
}

impl From<ProcessLifecycleRecord> for ExitRecord {
    fn from(record: ProcessLifecycleRecord) -> Self {
        Self {
            pid: record.pid,
            ppid: record.ppid,
            tid: record.tid,
            ptid: record.ptid,
            time: record.time,
        }
    }
}

fn parse_mmap_range(payload: &[u8]) -> Result<MmapRange, String> {
    Ok(MmapRange {
        pid: read_u32(payload, 0)?,
        tid: read_u32(payload, 4)?,
        start: read_u64(payload, 8)?,
        len: read_u64(payload, 16)?,
        pgoff: read_u64(payload, 24)?,
    })
}

fn parse_c_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn to_usize(value: u64, name: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{name} does not fit in usize"))
}
