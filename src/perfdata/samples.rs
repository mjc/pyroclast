use crate::perfdata::endian::{read_u32, read_u64};

pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub const PERF_SAMPLE_ADDR: u64 = 1 << 3;
pub const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
pub const PERF_SAMPLE_ID: u64 = 1 << 6;
pub const PERF_SAMPLE_CPU: u64 = 1 << 7;
pub const PERF_SAMPLE_PERIOD: u64 = 1 << 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleLayout {
    pub sample_type: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleRecord {
    pub ip: Option<u64>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub callchain: Vec<u64>,
}

pub fn parse_sample_record(payload: &[u8], layout: SampleLayout) -> Result<SampleRecord, String> {
    let mut cursor = SampleCursor::new(payload);
    let mut sample = SampleRecord {
        ip: None,
        pid: None,
        tid: None,
        callchain: Vec::new(),
    };

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
    if layout.has(PERF_SAMPLE_CPU) {
        cursor.skip_u32()?;
        cursor.skip_u32()?;
    }
    if layout.has(PERF_SAMPLE_PERIOD) {
        cursor.skip_u64()?;
    }
    if layout.has(PERF_SAMPLE_CALLCHAIN) {
        let callchain_len = cursor.read_u64()? as usize;
        for _ in 0..callchain_len {
            sample.callchain.push(cursor.read_u64()?);
        }
    }

    Ok(sample)
}

pub fn is_perf_context_marker(frame: u64) -> bool {
    frame >= 0xffff_ffff_ffff_f000
}

impl SampleLayout {
    fn has(self, flag: u64) -> bool {
        self.sample_type & flag != 0
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
        let value = read_u32(self.payload, self.offset)?;
        self.offset += 4;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        let value = read_u64(self.payload, self.offset)?;
        self.offset += 8;
        Ok(value)
    }

    fn skip_u32(&mut self) -> Result<(), String> {
        self.read_u32().map(|_| ())
    }

    fn skip_u64(&mut self) -> Result<(), String> {
        self.read_u64().map(|_| ())
    }
}
