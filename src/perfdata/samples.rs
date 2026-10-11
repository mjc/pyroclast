use crate::perfdata::endian::{read_u32, read_u64};

#[cfg(test)]
thread_local! {
    static SAMPLE_METADATA_PARSER_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn count_sample_metadata_parser_calls<T>(run: impl FnOnce() -> T) -> (T, usize) {
    struct Restore(usize);

    impl Drop for Restore {
        fn drop(&mut self) {
            SAMPLE_METADATA_PARSER_CALLS.with(|calls| calls.set(self.0));
        }
    }

    let previous = SAMPLE_METADATA_PARSER_CALLS.get();
    SAMPLE_METADATA_PARSER_CALLS.set(0);
    let restore = Restore(previous);
    let result = run();
    let calls = SAMPLE_METADATA_PARSER_CALLS.get();
    drop(restore);
    (result, calls)
}

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
    /// Event IP, independent of the recorded chain (perf `event.c:machine__resolve`).
    pub sample_ip: Option<u64>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub time: Option<u64>,
    pub cpu: Option<u32>,
    pub period: Option<u64>,
    pub frames: SampleCallchainFrames<'a>,
    pub(crate) callchain_range: Option<std::ops::Range<usize>>,
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
    single_ip: Option<u64>,
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
    parse_sample_callchain(payload, layout, false)
}

pub(super) fn parse_sample_record_metadata(
    payload: &[u8],
    layout: SampleLayout,
) -> Result<Option<SampleCallchain<'_>>, String> {
    #[cfg(test)]
    SAMPLE_METADATA_PARSER_CALLS.with(|calls| calls.set(calls.get() + 1));
    parse_sample_callchain(payload, layout, true)
}

fn parse_sample_callchain(
    payload: &[u8],
    layout: SampleLayout,
    retain_metadata: bool,
) -> Result<Option<SampleCallchain<'_>>, String> {
    layout.reject_unsupported_flags()?;
    let mut cursor = SampleCursor::new(payload);
    let mut pid = None;
    let mut tid = None;
    let mut time = None;
    let mut cpu = None;
    let mut period = None;
    let mut sample_ip = None;

    if layout.has(PERF_SAMPLE_IDENTIFIER) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_IP) {
        sample_ip = Some(cursor.read_u64()?);
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
        cpu = Some(cursor.read_u32()?);
        cursor.skip_u32()?;
    }
    if layout.has(PERF_SAMPLE_PERIOD) {
        period = Some(cursor.read_u64()?);
    }
    if layout.has(PERF_SAMPLE_READ) {
        cursor.skip_read_format(layout.read_format)?;
    }
    if !layout.has(PERF_SAMPLE_CALLCHAIN) && !retain_metadata {
        cursor.skip_non_callchain_tail(layout)?;
        return Ok(sample_ip.map(|ip| SampleCallchain {
            sample_ip,
            pid,
            tid,
            time,
            cpu,
            period,
            frames: SampleCallchainFrames::from_ip(Some(ip)),
            callchain_range: None,
            user_regs: None,
            user_stack: None,
        }));
    }

    let (frames, callchain_range) = if layout.has(PERF_SAMPLE_CALLCHAIN) {
        let callchain_start = cursor.offset;
        let callchain_len = usize::try_from(cursor.read_u64()?)
            .map_err(|_| "perf sample callchain length does not fit in usize".to_string())?;
        let callchain_bytes = callchain_len
            .checked_mul(8)
            .ok_or_else(|| "perf sample callchain byte length overflows usize".to_string())?;
        let frames = cursor.read_bytes(callchain_bytes)?;
        (
            SampleCallchainFrames {
                payload: frames,
                single_ip: None,
            },
            Some(callchain_start..cursor.offset),
        )
    } else {
        (SampleCallchainFrames::from_ip(sample_ip), None)
    };
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
        sample_ip,
        pid,
        tid,
        time,
        cpu,
        period,
        frames,
        callchain_range,
        user_regs,
        user_stack,
    }))
}

#[must_use]
pub fn is_perf_context_marker(frame: u64) -> bool {
    // linux/include/uapi/linux/perf_event.h: PERF_CONTEXT_MAX = (__u64)-4095.
    frame >= 0xffff_ffff_ffff_f001
}

#[must_use]
pub fn is_perf_user_context_marker(frame: u64) -> bool {
    frame == 0xffff_ffff_ffff_fe00
}

#[must_use]
pub fn is_perf_user_deferred_context_marker(frame: u64) -> bool {
    frame == 0xffff_ffff_ffff_fd80
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
    fn from_ip(ip: Option<u64>) -> Self {
        Self {
            payload: &[],
            single_ip: ip,
        }
    }

    pub(crate) fn deferred_cookie(&self) -> Option<u64> {
        let tail = self.payload.get(self.payload.len().checked_sub(16)?..)?;
        let marker = u64::from_le_bytes(tail[..8].try_into().ok()?);
        is_perf_user_deferred_context_marker(marker)
            .then(|| u64::from_le_bytes(tail[8..].try_into().unwrap()))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.payload.len() / 8 + usize::from(self.single_ip.is_some())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty() && self.single_ip.is_none()
    }
}

impl Iterator for SampleCallchainFrames<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ip) = self.single_ip.take() {
            return Some(ip);
        }
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

    fn skip_non_callchain_tail(&mut self, layout: SampleLayout) -> Result<(), String> {
        if layout.has(PERF_SAMPLE_RAW) {
            self.skip_sized_u32_payload()?;
        }
        if layout.has(PERF_SAMPLE_BRANCH_STACK) {
            self.skip_branch_stack(layout.branch_sample_type)?;
        }
        if layout.has(PERF_SAMPLE_REGS_USER) {
            self.skip_regs(layout.sample_regs_user)?;
        }
        if layout.has(PERF_SAMPLE_STACK_USER) {
            self.skip_user_stack()?;
        }
        Ok(())
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
        // perf 7.2.9 evsel.c:3703-3720 reads data[size] without padding,
        // then rejects a dynamic extent larger than the captured size.
        let bytes = self.read_bytes(size)?;
        let dynamic_size = self.read_u64()?;
        if dynamic_size > size as u64 {
            return Err("perf sample user stack dynamic size exceeds captured size".to_string());
        }
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

#[cfg(test)]
mod stack_extent_tests {
    use super::{
        PERF_SAMPLE_IP, PERF_SAMPLE_STACK_USER, SampleLayout, parse_sample_record_metadata,
    };

    fn metadata_stack_payload(size: usize, dynamic_size: u64) -> (Vec<u8>, SampleLayout) {
        let mut payload = 0x1000_u64.to_le_bytes().to_vec();
        payload.extend((size as u64).to_le_bytes());
        payload.extend(std::iter::repeat_n(0xa5, size));
        if size != 0 {
            payload.extend(dynamic_size.to_le_bytes());
        }
        let layout = SampleLayout {
            sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_STACK_USER,
            read_format: 0,
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
            sample_id_all: false,
        };
        (payload, layout)
    }

    fn assert_metadata_extents(sizes: &[usize]) {
        let mut failures = Vec::new();
        for &size in sizes {
            for dynamic_size in [0, size.saturating_sub(1) as u64, size as u64] {
                let (payload, layout) = metadata_stack_payload(size, dynamic_size);
                let parsed = parse_sample_record_metadata(&payload, layout);
                let correct = parsed.as_ref().is_ok_and(|sample| {
                    sample.as_ref().is_some_and(|sample| {
                        sample.sample_ip == Some(0x1000)
                            && sample.frames.clone().collect::<Vec<_>>() == [0x1000]
                            && sample.user_stack.as_ref().is_some_and(|stack| {
                                stack.bytes == vec![0xa5; size]
                                    && stack.dynamic_size == dynamic_size
                            })
                    })
                });
                if !correct {
                    failures.push(format!("size={size} dynamic={dynamic_size}: {parsed:?}"));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn summary_metadata_preserves_unpadded_captured_stack_extents() {
        // Native parser format (installed perf 7.2.9 evsel.c:3703-3720), not
        // a claim that typical kernel-requested dump sizes are unaligned.
        assert_metadata_extents(&[1, 2, 3, 4, 5, 6, 7, 9, 15, 17]);
    }

    #[test]
    fn summary_metadata_preserves_aligned_zero_equal_and_below_stack_extents() {
        assert_metadata_extents(&[0, 8, 16]);
    }

    #[test]
    fn summary_metadata_rejects_dynamic_extent_larger_than_capture() {
        let mut accepted = Vec::new();
        for size in [8, 16] {
            for dynamic_size in [size as u64 + 1, u64::MAX] {
                let (payload, layout) = metadata_stack_payload(size, dynamic_size);
                if parse_sample_record_metadata(&payload, layout).is_ok() {
                    accepted.push((size, dynamic_size));
                }
            }
        }
        assert!(
            accepted.is_empty(),
            "invalid extents accepted: {accepted:?}"
        );
    }

    #[test]
    fn summary_metadata_rejects_truncated_static_and_dynamic_stack_extents() {
        for size in [1, 8, 9] {
            let (payload, layout) = metadata_stack_payload(size, 0);
            for end in 0..payload.len() {
                assert!(
                    parse_sample_record_metadata(&payload[..end], layout).is_err(),
                    "size={size} end={end}"
                );
            }
        }
    }
}
