use std::collections::BTreeMap;
use std::path::Path;

use super::PerfProfileSummary;
use super::threads::ThreadProfileSummary;
use super::timeline::{TimelineBucket, TimelineSummary};
use crate::perfdata::fold::{PerfSampleMetadata, visit_perfdata_file_metadata};

pub(super) fn summarize_file(
    path: &Path,
    bucket_width_ns: u64,
    limit: usize,
) -> Result<PerfProfileSummary, String> {
    if bucket_width_ns == 0 {
        return Err("timeline bucket width must be greater than zero".to_string());
    }
    // The input need not be timestamp ordered. A first pass establishes the
    // exact origin and final thread names; a second creates sparse buckets.
    let mut first = None::<u64>;
    let metadata = visit_perfdata_file_metadata(path, |sample| {
        if let Some(time) = sample.time {
            first = Some(first.map_or(time, |first| first.min(time)));
        }
    })?;
    let mut aggregate = ProfileAggregate::default();
    visit_perfdata_file_metadata(path, |sample| {
        aggregate.record(sample, first, bucket_width_ns);
    })?;
    Ok(aggregate.finish(
        &metadata.comms_by_tid,
        metadata.lost_records,
        first,
        bucket_width_ns,
        limit,
    ))
}

#[derive(Default)]
struct ProfileAggregate {
    total_samples: usize,
    weighted_samples: u64,
    unassigned_samples: usize,
    untimed_samples: usize,
    last: Option<u64>,
    threads: BTreeMap<(Option<u32>, u32), ThreadProfileSummary>,
    buckets: BTreeMap<u64, TimelineBucket>,
}

impl ProfileAggregate {
    fn record(&mut self, sample: PerfSampleMetadata, first: Option<u64>, width: u64) {
        self.total_samples += 1;
        self.weighted_samples = self.weighted_samples.saturating_add(sample.period);
        if let Some(tid) = sample.tid.or(sample.pid) {
            let thread =
                self.threads
                    .entry((sample.pid, tid))
                    .or_insert_with(|| ThreadProfileSummary {
                        pid: sample.pid,
                        tid,
                        comm: String::new(),
                        samples: 0,
                        weighted_samples: 0,
                        first_sample_ns: None,
                        last_sample_ns: None,
                        cpus: Vec::new(),
                    });
            record_thread(thread, sample);
        } else {
            self.unassigned_samples += 1;
        }
        if let Some(time) = sample.time {
            self.last = Some(self.last.map_or(time, |last| last.max(time)));
            let start_offset_ns = (time - first.unwrap_or(time)) / width * width;
            let bucket = self
                .buckets
                .entry(start_offset_ns)
                .or_insert(TimelineBucket {
                    start_offset_ns,
                    samples: 0,
                    weighted_samples: 0,
                });
            bucket.samples += 1;
            bucket.weighted_samples = bucket.weighted_samples.saturating_add(sample.period);
        } else {
            self.untimed_samples += 1;
        }
    }

    fn finish(
        self,
        comms: &BTreeMap<u32, String>,
        lost_records: u64,
        first: Option<u64>,
        bucket_width_ns: u64,
        limit: usize,
    ) -> PerfProfileSummary {
        let mut threads = self.threads.into_values().collect::<Vec<_>>();
        for thread in &mut threads {
            thread.comm = comms
                .get(&thread.tid)
                .cloned()
                .unwrap_or_else(|| format!("tid {}", thread.tid));
            thread.cpus.sort_unstable();
        }
        threads.sort_by(|left, right| {
            right
                .weighted_samples
                .cmp(&left.weighted_samples)
                .then_with(|| left.tid.cmp(&right.tid))
                .then_with(|| left.pid.cmp(&right.pid))
        });
        threads.truncate(limit);
        PerfProfileSummary {
            total_samples: self.total_samples,
            weighted_samples: self.weighted_samples,
            lost_records,
            unassigned_samples: self.unassigned_samples,
            threads,
            timeline: TimelineSummary {
                bucket_width_ns,
                first_sample_ns: first,
                last_sample_ns: self.last,
                duration_ns: first.zip(self.last).map(|(first, last)| last - first),
                untimed_samples: self.untimed_samples,
                buckets: self.buckets.into_values().collect(),
            },
        }
    }
}

fn record_thread(thread: &mut ThreadProfileSummary, sample: PerfSampleMetadata) {
    thread.samples += 1;
    thread.weighted_samples = thread.weighted_samples.saturating_add(sample.period);
    if let Some(time) = sample.time {
        thread.first_sample_ns = Some(thread.first_sample_ns.map_or(time, |first| first.min(time)));
        thread.last_sample_ns = Some(thread.last_sample_ns.map_or(time, |last| last.max(time)));
    }
    if let Some(cpu) = sample.cpu
        && !thread.cpus.contains(&cpu)
    {
        thread.cpus.push(cpu);
    }
}
