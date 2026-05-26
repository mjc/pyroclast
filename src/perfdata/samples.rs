use crate::perfdata::endian::{read_u32, read_u64};

pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub const PERF_SAMPLE_ADDR: u64 = 1 << 3;
pub const PERF_SAMPLE_READ: u64 = 1 << 4;
pub const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
pub const PERF_SAMPLE_ID: u64 = 1 << 6;
pub const PERF_SAMPLE_CPU: u64 = 1 << 7;
pub const PERF_SAMPLE_PERIOD: u64 = 1 << 8;
pub const PERF_SAMPLE_STREAM_ID: u64 = 1 << 9;
pub const PERF_SAMPLE_RAW: u64 = 1 << 10;
pub const PERF_SAMPLE_BRANCH_STACK: u64 = 1 << 11;
pub const PERF_SAMPLE_REGS_USER: u64 = 1 << 12;
pub const PERF_SAMPLE_STACK_USER: u64 = 1 << 13;
pub const PERF_SAMPLE_WEIGHT: u64 = 1 << 14;
pub const PERF_SAMPLE_DATA_SRC: u64 = 1 << 15;
pub const PERF_SAMPLE_IDENTIFIER: u64 = 1 << 16;
pub const PERF_SAMPLE_TRANSACTION: u64 = 1 << 17;
pub const PERF_SAMPLE_REGS_INTR: u64 = 1 << 18;
pub const PERF_SAMPLE_PHYS_ADDR: u64 = 1 << 19;
pub const PERF_SAMPLE_AUX: u64 = 1 << 20;
pub const PERF_SAMPLE_CGROUP: u64 = 1 << 21;
pub const PERF_SAMPLE_DATA_PAGE_SIZE: u64 = 1 << 22;
pub const PERF_SAMPLE_CODE_PAGE_SIZE: u64 = 1 << 23;
pub const PERF_SAMPLE_WEIGHT_STRUCT: u64 = 1 << 24;
pub const PERF_SAMPLE_BRANCH_HW_INDEX: u64 = 1 << 17;
pub const PERF_SAMPLE_BRANCH_COUNTERS: u64 = 1 << 19;
pub const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
pub const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
pub const PERF_FORMAT_ID: u64 = 1 << 2;
pub const PERF_FORMAT_GROUP: u64 = 1 << 3;
pub const PERF_FORMAT_LOST: u64 = 1 << 4;

const SUPPORTED_PERF_SAMPLE_FLAGS: &[u64] = &[
    PERF_SAMPLE_IP,
    PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME,
    PERF_SAMPLE_ADDR,
    PERF_SAMPLE_READ,
    PERF_SAMPLE_CALLCHAIN,
    PERF_SAMPLE_ID,
    PERF_SAMPLE_CPU,
    PERF_SAMPLE_PERIOD,
    PERF_SAMPLE_STREAM_ID,
    PERF_SAMPLE_RAW,
    PERF_SAMPLE_BRANCH_STACK,
    PERF_SAMPLE_REGS_USER,
    PERF_SAMPLE_STACK_USER,
    PERF_SAMPLE_WEIGHT,
    PERF_SAMPLE_DATA_SRC,
    PERF_SAMPLE_IDENTIFIER,
    PERF_SAMPLE_TRANSACTION,
    PERF_SAMPLE_REGS_INTR,
    PERF_SAMPLE_PHYS_ADDR,
    PERF_SAMPLE_AUX,
    PERF_SAMPLE_CGROUP,
    PERF_SAMPLE_DATA_PAGE_SIZE,
    PERF_SAMPLE_CODE_PAGE_SIZE,
    PERF_SAMPLE_WEIGHT_STRUCT,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleLayout {
    pub sample_type: u64,
    pub read_format: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_regs_intr: u64,
    pub sample_id_all: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleRecord {
    pub ip: Option<u64>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub period: Option<u64>,
    pub callchain: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleCallchain<'a> {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub time: Option<u64>,
    pub period: Option<u64>,
    pub frames: SampleCallchainFrames<'a>,
    pub user_regs: Option<SampleUserRegs>,
    pub user_stack: Option<SampleUserStack<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleUserRegs {
    pub abi: u64,
    pub values: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleUserStack<'a> {
    pub bytes: &'a [u8],
    pub dynamic_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleCallchainFrames<'a> {
    payload: &'a [u8],
}

#[must_use]
pub fn supported_perf_sample_flags() -> Vec<u64> {
    SUPPORTED_PERF_SAMPLE_FLAGS.to_vec()
}

/// Parses a `PERF_RECORD_SAMPLE` payload according to the provided layout.
///
/// # Errors
///
/// Returns an error when a field requested by the sample layout is truncated.
pub fn parse_sample_record(payload: &[u8], layout: SampleLayout) -> Result<SampleRecord, String> {
    layout.reject_unsupported_flags()?;
    let mut cursor = SampleCursor::new(payload);
    let mut sample = SampleRecord {
        ip: None,
        pid: None,
        tid: None,
        period: None,
        callchain: Vec::new(),
    };

    if layout.has(PERF_SAMPLE_IDENTIFIER) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_IP) {
        sample.ip = Some(cursor.read_u64()?);
    }
    // PERF_RECORD_SAMPLE fields are serialized in this kernel-defined order,
    // not in ascending flag order.
    if layout.has(PERF_SAMPLE_TID) {
        sample.pid = Some(cursor.read_u32()?);
        sample.tid = Some(cursor.read_u32()?);
    }
    if layout.has(PERF_SAMPLE_TIME) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_ADDR) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_ID) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_STREAM_ID) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_CPU) {
        cursor.skip_u32()?;
        cursor.skip_u32()?;
    }
    if layout.has(PERF_SAMPLE_PERIOD) {
        sample.period = Some(cursor.read_u64()?);
    }
    if layout.has(PERF_SAMPLE_READ) {
        cursor.skip_read_format(layout.read_format)?;
    }
    if layout.has(PERF_SAMPLE_CALLCHAIN) {
        let callchain_len = usize::try_from(cursor.read_u64()?)
            .map_err(|_| "perf sample callchain length does not fit in usize".to_string())?;
        for _ in 0..callchain_len {
            sample.callchain.push(cursor.read_u64()?);
        }
    }
    if layout.has(PERF_SAMPLE_RAW) {
        cursor.skip_sized_u32_payload()?;
    }
    if layout.has(PERF_SAMPLE_BRANCH_STACK) {
        cursor.skip_branch_stack(layout.branch_sample_type)?;
    }
    if layout.has(PERF_SAMPLE_REGS_USER) {
        cursor.skip_regs(layout.sample_regs_user)?;
    }
    if layout.has(PERF_SAMPLE_STACK_USER) {
        cursor.skip_user_stack()?;
    }
    if layout.has(PERF_SAMPLE_WEIGHT) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_WEIGHT_STRUCT) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_DATA_SRC) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_TRANSACTION) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_REGS_INTR) {
        cursor.skip_regs(layout.sample_regs_intr)?;
    }
    if layout.has(PERF_SAMPLE_PHYS_ADDR) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_AUX) {
        cursor.skip_sized_u64_payload()?;
    }
    if layout.has(PERF_SAMPLE_CGROUP) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_DATA_PAGE_SIZE) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_CODE_PAGE_SIZE) {
        cursor.skip_u64()?;
    }

    cursor.finish()?;

    Ok(sample)
}

/// Parses only the sample metadata and callchain frames needed for folding.
///
/// # Errors
///
/// Returns an error when a field requested by the sample layout is truncated.
pub fn parse_sample_record_callchain(
    payload: &[u8],
    layout: SampleLayout,
) -> Result<Option<SampleCallchain<'_>>, String> {
    layout.reject_unsupported_flags()?;
    let mut cursor = SampleCursor::new(payload);
    let mut pid = None;
    let mut tid = None;
    let mut time = None;
    let mut period = None;

    if layout.has(PERF_SAMPLE_IDENTIFIER) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_IP) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_TID) {
        pid = Some(cursor.read_u32()?);
        tid = Some(cursor.read_u32()?);
    }
    if layout.has(PERF_SAMPLE_TIME) {
        time = Some(cursor.read_u64()?);
    }
    if layout.has(PERF_SAMPLE_ADDR) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_ID) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_STREAM_ID) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_CPU) {
        cursor.skip_u32()?;
        cursor.skip_u32()?;
    }
    if layout.has(PERF_SAMPLE_PERIOD) {
        period = Some(cursor.read_u64()?);
    }
    if layout.has(PERF_SAMPLE_READ) {
        cursor.skip_read_format(layout.read_format)?;
    }
    if !layout.has(PERF_SAMPLE_CALLCHAIN) {
        return Ok(None);
    }

    let callchain_len = usize::try_from(cursor.read_u64()?)
        .map_err(|_| "perf sample callchain length does not fit in usize".to_string())?;
    let callchain_bytes = callchain_len
        .checked_mul(8)
        .ok_or_else(|| "perf sample callchain byte length overflows usize".to_string())?;
    let frames = cursor.read_bytes(callchain_bytes)?;
    let mut user_regs = None;
    let mut user_stack = None;

    if layout.has(PERF_SAMPLE_RAW) {
        cursor.skip_sized_u32_payload()?;
    }
    if layout.has(PERF_SAMPLE_BRANCH_STACK) {
        cursor.skip_branch_stack(layout.branch_sample_type)?;
    }
    if layout.has(PERF_SAMPLE_REGS_USER) {
        user_regs = Some(cursor.read_regs(layout.sample_regs_user)?);
    }
    if layout.has(PERF_SAMPLE_STACK_USER) {
        user_stack = Some(cursor.read_user_stack()?);
    }

    Ok(Some(SampleCallchain {
        pid,
        tid,
        time,
        period,
        frames: SampleCallchainFrames { payload: frames },
        user_regs,
        user_stack,
    }))
}

#[must_use]
pub fn is_perf_context_marker(frame: u64) -> bool {
    frame >= 0xffff_ffff_ffff_f000
}

#[must_use]
pub fn is_perf_user_context_marker(frame: u64) -> bool {
    frame == 0xffff_ffff_ffff_fe00
}

#[must_use]
pub fn is_kernel_space_frame(frame: u64) -> bool {
    frame >= 0xffff_8000_0000_0000 && !is_perf_context_marker(frame)
}

impl SampleLayout {
    fn has(self, flag: u64) -> bool {
        self.sample_type & flag != 0
    }

    fn reject_unsupported_flags(self) -> Result<(), String> {
        let unsupported = self.sample_type & !supported_perf_sample_mask();
        if unsupported == 0 {
            Ok(())
        } else {
            Err(format!("unsupported perf sample flags: 0x{unsupported:x}"))
        }
    }
}

fn supported_perf_sample_mask() -> u64 {
    SUPPORTED_PERF_SAMPLE_FLAGS
        .iter()
        .copied()
        .fold(0, |mask, flag| mask | flag)
}

impl SampleCallchainFrames<'_> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.payload.len() / 8
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

impl Iterator for SampleCallchainFrames<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let (frame, remaining) = self.payload.split_first_chunk::<8>()?;
        self.payload = remaining;
        Some(u64::from_le_bytes(*frame))
    }
}

struct SampleCursor<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> SampleCursor<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self { payload, offset: 0 }
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let value = read_u32(self.payload, self.offset)
            .map_err(|_| "perf sample payload is truncated".to_string())?;
        self.offset += 4;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        let value = read_u64(self.payload, self.offset)
            .map_err(|_| "perf sample payload is truncated".to_string())?;
        self.offset += 8;
        Ok(value)
    }

    fn skip_u32(&mut self) -> Result<(), String> {
        self.read_u32().map(|_| ())
    }

    fn skip_u64(&mut self) -> Result<(), String> {
        self.read_u64().map(|_| ())
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "perf sample field offset overflows usize".to_string())?;
        let bytes = self
            .payload
            .get(self.offset..end)
            .ok_or_else(|| "perf sample payload is truncated".to_string())?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), String> {
        if self.offset == self.payload.len() {
            Ok(())
        } else {
            Err("perf sample payload has trailing bytes".to_string())
        }
    }

    fn skip_sized_u32_payload(&mut self) -> Result<(), String> {
        let size = usize::try_from(self.read_u32()?)
            .map_err(|_| "perf sample raw size does not fit in usize".to_string())?;
        self.read_bytes(size).map(|_| ())
    }

    fn skip_sized_u64_payload(&mut self) -> Result<(), String> {
        let size = usize::try_from(self.read_u64()?)
            .map_err(|_| "perf sample aux size does not fit in usize".to_string())?;
        self.read_bytes(size).map(|_| ())
    }

    fn skip_branch_stack(&mut self, branch_sample_type: u64) -> Result<(), String> {
        let branches = usize::try_from(self.read_u64()?)
            .map_err(|_| "perf sample branch count does not fit in usize".to_string())?;
        if branch_sample_type & PERF_SAMPLE_BRANCH_HW_INDEX != 0 {
            self.skip_u64()?;
        }
        let byte_len = branches
            .checked_mul(24)
            .ok_or_else(|| "perf sample branch stack byte length overflows usize".to_string())?;
        self.read_bytes(byte_len)?;
        if branch_sample_type & PERF_SAMPLE_BRANCH_COUNTERS != 0 {
            let counter_bytes = branches.checked_mul(8).ok_or_else(|| {
                "perf sample branch counter byte length overflows usize".to_string()
            })?;
            self.read_bytes(counter_bytes)?;
        }
        Ok(())
    }

    fn skip_regs(&mut self, mask: u64) -> Result<(), String> {
        self.read_regs(mask).map(|_| ())
    }

    fn skip_user_stack(&mut self) -> Result<(), String> {
        self.read_user_stack().map(|_| ())
    }

    fn read_regs(&mut self, mask: u64) -> Result<SampleUserRegs, String> {
        let abi = self.read_u64()?;
        let register_count = if abi == 0 {
            0
        } else {
            mask.count_ones() as usize
        };
        let mut values = Vec::with_capacity(register_count);
        for _ in 0..register_count {
            values.push(self.read_u64()?);
        }
        Ok(SampleUserRegs { abi, values })
    }

    fn read_user_stack(&mut self) -> Result<SampleUserStack<'a>, String> {
        let size = usize::try_from(self.read_u64()?)
            .map_err(|_| "perf sample user stack size does not fit in usize".to_string())?;
        if size == 0 {
            return Ok(SampleUserStack {
                bytes: &[],
                dynamic_size: 0,
            });
        }
        let bytes = self.read_bytes(size)?;
        let padding = size.next_multiple_of(8) - size;
        self.read_bytes(padding)?;
        let dynamic_size = self.read_u64()?;
        Ok(SampleUserStack {
            bytes,
            dynamic_size,
        })
    }

    fn skip_read_format(&mut self, read_format: u64) -> Result<(), String> {
        if read_format & PERF_FORMAT_GROUP != 0 {
            return self.skip_group_read_format(read_format);
        }

        self.skip_u64()?;
        if read_format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
            self.skip_u64()?;
        }
        if read_format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
            self.skip_u64()?;
        }
        if read_format & PERF_FORMAT_ID != 0 {
            self.skip_u64()?;
        }
        if read_format & PERF_FORMAT_LOST != 0 {
            self.skip_u64()?;
        }

        Ok(())
    }

    fn skip_group_read_format(&mut self, read_format: u64) -> Result<(), String> {
        let values = usize::try_from(self.read_u64()?)
            .map_err(|_| "perf sample read group count does not fit in usize".to_string())?;
        if read_format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
            self.skip_u64()?;
        }
        if read_format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
            self.skip_u64()?;
        }

        for _ in 0..values {
            self.skip_u64()?;
            if read_format & PERF_FORMAT_ID != 0 {
                self.skip_u64()?;
            }
            if read_format & PERF_FORMAT_LOST != 0 {
                self.skip_u64()?;
            }
        }

        Ok(())
    }
}
