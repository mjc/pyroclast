mod common;

use common::{file_attr_bytes, perfdata_with_attrs};
use pyroclast::perfdata::attrs::{PerfFileAttr, parse_file_attrs};
use pyroclast::perfdata::header::PerfHeader;
use pyroclast::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID};

#[test]
fn parses_sample_type_from_file_attr_section() {
    let sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
    let bytes = perfdata_with_attrs([file_attr_bytes(sample_type, 512, 24)]);
    let header = PerfHeader {
        header_size: 104,
        attr_offset: 104,
        attr_size: 144,
        data_offset: 248,
        data_size: 0,
    };

    let attrs = parse_file_attrs(&bytes, header).expect("attrs");

    assert_eq!(
        attrs,
        vec![PerfFileAttr {
            sample_type,
            ids_offset: 512,
            ids_size: 24,
        }]
    );
}
