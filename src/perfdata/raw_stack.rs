use rustc_hash::FxHashMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollapsedRawStack {
    pub pid: Option<u32>,
    pub callchain: Vec<u64>,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct RawStackKey {
    pid: Option<u32>,
    callchain: Vec<u64>,
}

#[derive(Debug, Default)]
pub struct RawStackAccumulator {
    counts: FxHashMap<RawStackKey, u64>,
}

impl RawStackAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add<I>(&mut self, pid: Option<u32>, callchain: I, count: u64)
    where
        I: IntoIterator<Item = u64>,
    {
        let key = RawStackKey {
            pid,
            callchain: callchain.into_iter().collect(),
        };
        *self.counts.entry(key).or_insert(0) += count;
    }

    #[must_use]
    pub fn into_collapsed(self) -> Vec<CollapsedRawStack> {
        let mut collapsed = self
            .counts
            .into_iter()
            .map(|(key, count)| CollapsedRawStack {
                pid: key.pid,
                callchain: key.callchain,
                count,
            })
            .collect::<Vec<_>>();
        collapsed.sort_by(|left, right| {
            left.pid
                .cmp(&right.pid)
                .then_with(|| left.callchain.cmp(&right.callchain))
        });
        collapsed
    }
}

#[cfg(test)]
mod tests {
    use super::RawStackAccumulator;

    #[test]
    fn accumulates_identical_raw_stacks() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add(Some(7), [0x1000, 0x2000], 1);
        accumulator.add(Some(7), [0x1000, 0x2000], 3);
        accumulator.add(Some(8), [0x1000, 0x2000], 1);

        let collapsed = accumulator.into_collapsed();

        assert_eq!(collapsed.len(), 2);
        assert_eq!(collapsed[0].pid, Some(7));
        assert_eq!(collapsed[0].callchain, vec![0x1000, 0x2000]);
        assert_eq!(collapsed[0].count, 4);
        assert_eq!(collapsed[1].pid, Some(8));
        assert_eq!(collapsed[1].count, 1);
    }
}
