use crate::perfdata::endian::{read_u32, read_u64};

pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;

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
    let mut offset = 0;
    let mut sample = SampleRecord {
        ip: None,
        pid: None,
        tid: None,
        callchain: Vec::new(),
    };

    if layout.has(PERF_SAMPLE_IP) {
        sample.ip = Some(read_u64(payload, offset)?);
        offset += 8;
    }
    if layout.has(PERF_SAMPLE_TID) {
        sample.pid = Some(read_u32(payload, offset)?);
        sample.tid = Some(read_u32(payload, offset + 4)?);
        offset += 8;
    }
    if layout.has(PERF_SAMPLE_CALLCHAIN) {
        let callchain_len = read_u64(payload, offset)? as usize;
        offset += 8;
        for _ in 0..callchain_len {
            sample.callchain.push(read_u64(payload, offset)?);
            offset += 8;
        }
    }

    Ok(sample)
}

impl SampleLayout {
    fn has(self, flag: u64) -> bool {
        self.sample_type & flag != 0
    }
}
