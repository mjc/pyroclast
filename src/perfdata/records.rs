use crate::perfdata::endian::{read_u16, read_u32, read_u64};
use crate::perfdata::header::PerfHeader;

pub const PERF_RECORD_MMAP: u32 = 1;
pub const PERF_RECORD_LOST: u32 = 2;
pub const PERF_RECORD_COMM: u32 = 3;
pub const PERF_RECORD_EXIT: u32 = 4;
pub const PERF_RECORD_THROTTLE: u32 = 5;
pub const PERF_RECORD_UNTHROTTLE: u32 = 6;
pub const PERF_RECORD_FORK: u32 = 7;
pub const PERF_RECORD_READ: u32 = 8;
pub const PERF_RECORD_SAMPLE: u32 = 9;
pub const PERF_RECORD_MMAP2: u32 = 10;
pub const PERF_RECORD_AUX: u32 = 11;
pub const PERF_RECORD_ITRACE_START: u32 = 12;
pub const PERF_RECORD_LOST_SAMPLES: u32 = 13;
pub const PERF_RECORD_SWITCH: u32 = 14;
pub const PERF_RECORD_SWITCH_CPU_WIDE: u32 = 15;
pub const PERF_RECORD_NAMESPACES: u32 = 16;
pub const PERF_RECORD_KSYMBOL: u32 = 17;
pub const PERF_RECORD_BPF_EVENT: u32 = 18;
pub const PERF_RECORD_CGROUP: u32 = 19;
pub const PERF_RECORD_TEXT_POKE: u32 = 20;
pub const PERF_RECORD_AUX_OUTPUT_HW_ID: u32 = 21;
pub const PERF_RECORD_CALLCHAIN_DEFERRED: u32 = 22;
pub const PERF_RECORD_MISC_MMAP_BUILD_ID: u16 = 1 << 14;
const BPF_TAG_SIZE: usize = 8;

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
pub enum ParsedRecord {
    Comm(CommRecord),
    Mmap(MmapRecord),
    Mmap2(Mmap2Record),
    Mmap2BuildId(Mmap2BuildIdRecord),
    Fork(ForkRecord),
    Exit(ExitRecord),
    Lost(LostRecord),
    LostSamples(LostSamplesRecord),
    Throttle(ThrottleRecord),
    Unthrottle(UnthrottleRecord),
    Read(ReadRecord),
    Sample(SamplePayloadRecord),
    Aux(AuxRecord),
    ItraceStart(ItraceStartRecord),
    Switch(SwitchRecord),
    SwitchCpuWide(SwitchCpuWideRecord),
    Namespaces(NamespacesRecord),
    Ksymbol(KsymbolRecord),
    BpfEvent(BpfEventRecord),
    Cgroup(CgroupRecord),
    TextPoke(TextPokeRecord),
    AuxOutputHwId(AuxOutputHwIdRecord),
    CallchainDeferred(CallchainDeferredRecord),
    Unsupported { record_type: u32 },
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mmap2BuildIdRecord {
    pub pid: u32,
    pub tid: u32,
    pub start: u64,
    pub len: u64,
    pub pgoff: u64,
    pub build_id_size: u8,
    pub build_id: Vec<u8>,
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
pub struct ThrottleRecord {
    pub time: u64,
    pub id: u64,
    pub stream_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnthrottleRecord {
    pub time: u64,
    pub id: u64,
    pub stream_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRecord {
    pub pid: u32,
    pub tid: u32,
    pub values: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SamplePayloadRecord {
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxRecord {
    pub aux_offset: u64,
    pub aux_size: u64,
    pub flags: u64,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItraceStartRecord {
    pub pid: u32,
    pub tid: u32,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchRecord {
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchCpuWideRecord {
    pub next_prev_pid: u32,
    pub next_prev_tid: u32,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacesRecord {
    pub pid: u32,
    pub tid: u32,
    pub namespaces: Vec<NamespaceLink>,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceLink {
    pub dev: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KsymbolRecord {
    pub addr: u64,
    pub len: u32,
    pub ksym_type: u16,
    pub flags: u16,
    pub name: String,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BpfEventRecord {
    pub event_type: u16,
    pub flags: u16,
    pub id: u32,
    pub tag: [u8; BPF_TAG_SIZE],
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupRecord {
    pub id: u64,
    pub path: String,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextPokeRecord {
    pub addr: u64,
    pub old_len: u16,
    pub new_len: u16,
    pub bytes: Vec<u8>,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxOutputHwIdRecord {
    pub hw_id: u64,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallchainDeferredRecord {
    pub cookie: u64,
    pub ips: Vec<u64>,
    pub sample_id: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThrottleEventRecord {
    time: u64,
    id: u64,
    stream_id: u64,
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

/// Parses a perf record into a typed payload when Pyroclast supports it.
///
/// # Errors
///
/// Returns an error when a supported record payload is malformed.
pub fn parse_record(record: PerfRecord<'_>) -> Result<ParsedRecord, String> {
    match record.header.record_type {
        PERF_RECORD_MMAP => parse_mmap_record(record.payload).map(ParsedRecord::Mmap),
        PERF_RECORD_LOST => parse_lost_record(record.payload).map(ParsedRecord::Lost),
        PERF_RECORD_COMM => parse_comm_record(record.payload).map(ParsedRecord::Comm),
        PERF_RECORD_THROTTLE => parse_throttle_record(record.payload).map(ParsedRecord::Throttle),
        PERF_RECORD_UNTHROTTLE => {
            parse_unthrottle_record(record.payload).map(ParsedRecord::Unthrottle)
        }
        PERF_RECORD_MMAP2 if has_misc_flag(record.header.misc, PERF_RECORD_MISC_MMAP_BUILD_ID) => {
            parse_mmap2_build_id_record(record.payload).map(ParsedRecord::Mmap2BuildId)
        }
        PERF_RECORD_MMAP2 => parse_mmap2_record(record.payload).map(ParsedRecord::Mmap2),
        PERF_RECORD_LOST_SAMPLES => {
            parse_lost_samples_record(record.payload).map(ParsedRecord::LostSamples)
        }
        PERF_RECORD_EXIT => parse_exit_record(record.payload).map(ParsedRecord::Exit),
        PERF_RECORD_FORK => parse_fork_record(record.payload).map(ParsedRecord::Fork),
        PERF_RECORD_READ => parse_read_record(record.payload).map(ParsedRecord::Read),
        PERF_RECORD_SAMPLE => parse_sample_payload_record(record.payload).map(ParsedRecord::Sample),
        PERF_RECORD_AUX => parse_aux_record(record.payload).map(ParsedRecord::Aux),
        PERF_RECORD_ITRACE_START => {
            parse_itrace_start_record(record.payload).map(ParsedRecord::ItraceStart)
        }
        PERF_RECORD_SWITCH => parse_switch_record(record.payload).map(ParsedRecord::Switch),
        PERF_RECORD_SWITCH_CPU_WIDE => {
            parse_switch_cpu_wide_record(record.payload).map(ParsedRecord::SwitchCpuWide)
        }
        PERF_RECORD_NAMESPACES => {
            parse_namespaces_record(record.payload).map(ParsedRecord::Namespaces)
        }
        PERF_RECORD_KSYMBOL => parse_ksymbol_record(record.payload).map(ParsedRecord::Ksymbol),
        PERF_RECORD_BPF_EVENT => parse_bpf_event_record(record.payload).map(ParsedRecord::BpfEvent),
        PERF_RECORD_CGROUP => parse_cgroup_record(record.payload).map(ParsedRecord::Cgroup),
        PERF_RECORD_TEXT_POKE => parse_text_poke_record(record.payload).map(ParsedRecord::TextPoke),
        PERF_RECORD_AUX_OUTPUT_HW_ID => {
            parse_aux_output_hw_id_record(record.payload).map(ParsedRecord::AuxOutputHwId)
        }
        PERF_RECORD_CALLCHAIN_DEFERRED => {
            parse_callchain_deferred_record(record.payload).map(ParsedRecord::CallchainDeferred)
        }
        record_type => Ok(ParsedRecord::Unsupported { record_type }),
    }
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

/// Parses a `PERF_RECORD_MMAP2` payload carrying build-id data.
///
/// # Errors
///
/// Returns an error when the fixed mapping or build-id fields are missing.
pub fn parse_mmap2_build_id_record(payload: &[u8]) -> Result<Mmap2BuildIdRecord, String> {
    if payload.len() < 64 {
        return Err("PERF_RECORD_MMAP2 build-id payload is shorter than 64 bytes".to_string());
    }
    let range = parse_mmap_range(payload)?;
    let build_id_size = payload[32];
    let build_id_end = 36usize
        .checked_add(usize::from(build_id_size))
        .ok_or_else(|| "PERF_RECORD_MMAP2 build-id size overflows usize".to_string())?;
    if build_id_end > 56 {
        return Err(format!(
            "PERF_RECORD_MMAP2 build-id size {build_id_size} exceeds 20 bytes"
        ));
    }
    let build_id = payload[36..build_id_end].to_vec();
    let prot = read_u32(payload, 56)?;
    let flags = read_u32(payload, 60)?;
    let path = parse_c_string(&payload[64..]);

    Ok(Mmap2BuildIdRecord {
        pid: range.pid,
        tid: range.tid,
        start: range.start,
        len: range.len,
        pgoff: range.pgoff,
        build_id_size,
        build_id,
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

/// Parses a `PERF_RECORD_THROTTLE` payload.
///
/// # Errors
///
/// Returns an error when the fixed `time`/`id`/`stream_id` fields are missing.
pub fn parse_throttle_record(payload: &[u8]) -> Result<ThrottleRecord, String> {
    let record = parse_throttle_event_record(payload, "PERF_RECORD_THROTTLE")?;

    Ok(ThrottleRecord::from(record))
}

/// Parses a `PERF_RECORD_UNTHROTTLE` payload.
///
/// # Errors
///
/// Returns an error when the fixed `time`/`id`/`stream_id` fields are missing.
pub fn parse_unthrottle_record(payload: &[u8]) -> Result<UnthrottleRecord, String> {
    let record = parse_throttle_event_record(payload, "PERF_RECORD_UNTHROTTLE")?;

    Ok(UnthrottleRecord::from(record))
}

/// Parses a `PERF_RECORD_READ` payload.
///
/// The nested `read_format` bytes depend on `perf_event_attr.read_format`, so
/// this parser preserves them losslessly for an attr-aware layer to decode.
///
/// # Errors
///
/// Returns an error when the fixed `pid`/`tid` fields are missing.
pub fn parse_read_record(payload: &[u8]) -> Result<ReadRecord, String> {
    if payload.len() < 8 {
        return Err("PERF_RECORD_READ payload is shorter than 8 bytes".to_string());
    }

    Ok(ReadRecord {
        pid: read_u32(payload, 0)?,
        tid: read_u32(payload, 4)?,
        values: payload[8..].to_vec(),
    })
}

/// Parses a `PERF_RECORD_SAMPLE` payload losslessly.
///
/// Field interpretation depends on `perf_event_attr.sample_type`; callers that
/// have attr context should use the sample module to decode the payload.
///
/// # Errors
///
/// This parser currently has no fixed fields to reject.
pub fn parse_sample_payload_record(payload: &[u8]) -> Result<SamplePayloadRecord, String> {
    Ok(SamplePayloadRecord {
        payload: payload.to_vec(),
    })
}

/// Parses a `PERF_RECORD_AUX` payload.
///
/// # Errors
///
/// Returns an error when the fixed aux fields are missing.
pub fn parse_aux_record(payload: &[u8]) -> Result<AuxRecord, String> {
    if payload.len() < 24 {
        return Err("PERF_RECORD_AUX payload is shorter than 24 bytes".to_string());
    }

    Ok(AuxRecord {
        aux_offset: read_u64(payload, 0)?,
        aux_size: read_u64(payload, 8)?,
        flags: read_u64(payload, 16)?,
        sample_id: payload[24..].to_vec(),
    })
}

/// Parses a `PERF_RECORD_ITRACE_START` payload.
///
/// # Errors
///
/// Returns an error when the fixed pid/tid fields are missing.
pub fn parse_itrace_start_record(payload: &[u8]) -> Result<ItraceStartRecord, String> {
    if payload.len() < 8 {
        return Err("PERF_RECORD_ITRACE_START payload is shorter than 8 bytes".to_string());
    }

    Ok(ItraceStartRecord {
        pid: read_u32(payload, 0)?,
        tid: read_u32(payload, 4)?,
        sample_id: payload[8..].to_vec(),
    })
}

/// Parses a `PERF_RECORD_SWITCH` payload.
///
/// The payload is only the attr-dependent trailing `sample_id` block.
///
/// # Errors
///
/// This parser currently has no malformed fixed fields to reject.
pub fn parse_switch_record(payload: &[u8]) -> Result<SwitchRecord, String> {
    Ok(SwitchRecord {
        sample_id: payload.to_vec(),
    })
}

/// Parses a `PERF_RECORD_SWITCH_CPU_WIDE` payload.
///
/// # Errors
///
/// Returns an error when the fixed pid/tid fields are missing.
pub fn parse_switch_cpu_wide_record(payload: &[u8]) -> Result<SwitchCpuWideRecord, String> {
    if payload.len() < 8 {
        return Err("PERF_RECORD_SWITCH_CPU_WIDE payload is shorter than 8 bytes".to_string());
    }

    Ok(SwitchCpuWideRecord {
        next_prev_pid: read_u32(payload, 0)?,
        next_prev_tid: read_u32(payload, 4)?,
        sample_id: payload[8..].to_vec(),
    })
}

/// Parses a `PERF_RECORD_NAMESPACES` payload.
///
/// # Errors
///
/// Returns an error when the fixed fields or declared namespace entries are missing.
pub fn parse_namespaces_record(payload: &[u8]) -> Result<NamespacesRecord, String> {
    if payload.len() < 16 {
        return Err("PERF_RECORD_NAMESPACES payload is shorter than 16 bytes".to_string());
    }
    let nr_namespaces = to_usize(read_u64(payload, 8)?, "PERF_RECORD_NAMESPACES nr")?;
    let entries_len = nr_namespaces
        .checked_mul(16)
        .ok_or_else(|| "PERF_RECORD_NAMESPACES entries length overflows usize".to_string())?;
    let sample_offset = 16usize
        .checked_add(entries_len)
        .ok_or_else(|| "PERF_RECORD_NAMESPACES payload length overflows usize".to_string())?;
    if payload.len() < sample_offset {
        return Err(format!(
            "PERF_RECORD_NAMESPACES payload is shorter than declared {nr_namespaces} namespaces"
        ));
    }

    let mut namespaces = Vec::with_capacity(nr_namespaces);
    for index in 0..nr_namespaces {
        let offset = 16 + index * 16;
        namespaces.push(NamespaceLink {
            dev: read_u64(payload, offset)?,
            inode: read_u64(payload, offset + 8)?,
        });
    }

    Ok(NamespacesRecord {
        pid: read_u32(payload, 0)?,
        tid: read_u32(payload, 4)?,
        namespaces,
        sample_id: payload[sample_offset..].to_vec(),
    })
}

/// Parses a `PERF_RECORD_KSYMBOL` payload.
///
/// # Errors
///
/// Returns an error when the fixed ksymbol fields are missing.
pub fn parse_ksymbol_record(payload: &[u8]) -> Result<KsymbolRecord, String> {
    if payload.len() < 16 {
        return Err("PERF_RECORD_KSYMBOL payload is shorter than 16 bytes".to_string());
    }

    let (name, sample_id) = parse_c_string_with_remainder(&payload[16..]);
    Ok(KsymbolRecord {
        addr: read_u64(payload, 0)?,
        len: read_u32(payload, 8)?,
        ksym_type: read_u16(payload, 12)?,
        flags: read_u16(payload, 14)?,
        name,
        sample_id,
    })
}

/// Parses a `PERF_RECORD_BPF_EVENT` payload.
///
/// # Errors
///
/// Returns an error when the fixed BPF event fields are missing.
pub fn parse_bpf_event_record(payload: &[u8]) -> Result<BpfEventRecord, String> {
    if payload.len() < 16 {
        return Err("PERF_RECORD_BPF_EVENT payload is shorter than 16 bytes".to_string());
    }

    let mut tag = [0; BPF_TAG_SIZE];
    tag.copy_from_slice(&payload[8..16]);

    Ok(BpfEventRecord {
        event_type: read_u16(payload, 0)?,
        flags: read_u16(payload, 2)?,
        id: read_u32(payload, 4)?,
        tag,
        sample_id: payload[16..].to_vec(),
    })
}

/// Parses a `PERF_RECORD_CGROUP` payload.
///
/// # Errors
///
/// Returns an error when the fixed cgroup id field is missing.
pub fn parse_cgroup_record(payload: &[u8]) -> Result<CgroupRecord, String> {
    if payload.len() < 8 {
        return Err("PERF_RECORD_CGROUP payload is shorter than 8 bytes".to_string());
    }

    let (path, sample_id) = parse_c_string_with_remainder(&payload[8..]);
    Ok(CgroupRecord {
        id: read_u64(payload, 0)?,
        path,
        sample_id,
    })
}

/// Parses a `PERF_RECORD_TEXT_POKE` payload.
///
/// # Errors
///
/// Returns an error when the fixed text poke fields or declared bytes are missing.
pub fn parse_text_poke_record(payload: &[u8]) -> Result<TextPokeRecord, String> {
    if payload.len() < 12 {
        return Err("PERF_RECORD_TEXT_POKE payload is shorter than 12 bytes".to_string());
    }

    let old_len = read_u16(payload, 8)?;
    let new_len = read_u16(payload, 10)?;
    let byte_len = usize::from(old_len)
        .checked_add(usize::from(new_len))
        .ok_or_else(|| "PERF_RECORD_TEXT_POKE byte length overflows usize".to_string())?;
    let sample_offset = 12usize
        .checked_add(byte_len)
        .ok_or_else(|| "PERF_RECORD_TEXT_POKE payload length overflows usize".to_string())?;
    if payload.len() < sample_offset {
        return Err("PERF_RECORD_TEXT_POKE payload is shorter than declared bytes".to_string());
    }

    Ok(TextPokeRecord {
        addr: read_u64(payload, 0)?,
        old_len,
        new_len,
        bytes: payload[12..sample_offset].to_vec(),
        sample_id: payload[sample_offset..].to_vec(),
    })
}

/// Parses a `PERF_RECORD_AUX_OUTPUT_HW_ID` payload.
///
/// # Errors
///
/// Returns an error when the fixed hardware id field is missing.
pub fn parse_aux_output_hw_id_record(payload: &[u8]) -> Result<AuxOutputHwIdRecord, String> {
    if payload.len() < 8 {
        return Err("PERF_RECORD_AUX_OUTPUT_HW_ID payload is shorter than 8 bytes".to_string());
    }

    Ok(AuxOutputHwIdRecord {
        hw_id: read_u64(payload, 0)?,
        sample_id: payload[8..].to_vec(),
    })
}

/// Parses a `PERF_RECORD_CALLCHAIN_DEFERRED` payload.
///
/// # Errors
///
/// Returns an error when the fixed fields or declared instruction pointers are missing.
pub fn parse_callchain_deferred_record(payload: &[u8]) -> Result<CallchainDeferredRecord, String> {
    if payload.len() < 16 {
        return Err("PERF_RECORD_CALLCHAIN_DEFERRED payload is shorter than 16 bytes".to_string());
    }

    let nr = to_usize(read_u64(payload, 8)?, "PERF_RECORD_CALLCHAIN_DEFERRED nr")?;
    let ips_len = nr.checked_mul(8).ok_or_else(|| {
        "PERF_RECORD_CALLCHAIN_DEFERRED instruction pointer length overflows usize".to_string()
    })?;
    let sample_offset = 16usize.checked_add(ips_len).ok_or_else(|| {
        "PERF_RECORD_CALLCHAIN_DEFERRED payload length overflows usize".to_string()
    })?;
    if payload.len() < sample_offset {
        return Err(
            "PERF_RECORD_CALLCHAIN_DEFERRED payload is shorter than declared ips".to_string(),
        );
    }

    let mut ips = Vec::with_capacity(nr);
    for index in 0..nr {
        ips.push(read_u64(payload, 16 + index * 8)?);
    }

    Ok(CallchainDeferredRecord {
        cookie: read_u64(payload, 0)?,
        ips,
        sample_id: payload[sample_offset..].to_vec(),
    })
}

fn parse_throttle_event_record(
    payload: &[u8],
    record_name: &str,
) -> Result<ThrottleEventRecord, String> {
    if payload.len() < 24 {
        return Err(format!("{record_name} payload is shorter than 24 bytes"));
    }

    Ok(ThrottleEventRecord {
        time: read_u64(payload, 0)?,
        id: read_u64(payload, 8)?,
        stream_id: read_u64(payload, 16)?,
    })
}

impl From<ThrottleEventRecord> for ThrottleRecord {
    fn from(record: ThrottleEventRecord) -> Self {
        Self {
            time: record.time,
            id: record.id,
            stream_id: record.stream_id,
        }
    }
}

impl From<ThrottleEventRecord> for UnthrottleRecord {
    fn from(record: ThrottleEventRecord) -> Self {
        Self {
            time: record.time,
            id: record.id,
            stream_id: record.stream_id,
        }
    }
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

fn parse_c_string_with_remainder(bytes: &[u8]) -> (String, Vec<u8>) {
    let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
        return (String::from_utf8_lossy(bytes).into_owned(), Vec::new());
    };

    (
        String::from_utf8_lossy(&bytes[..end]).into_owned(),
        bytes[end + 1..].to_vec(),
    )
}

fn has_misc_flag(misc: u16, flag: u16) -> bool {
    misc & flag != 0
}

fn to_usize(value: u64, name: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{name} does not fit in usize"))
}
