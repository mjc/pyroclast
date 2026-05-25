use std::hash::{Hash, Hasher};

use hashbrown::HashMap;
use hashbrown::hash_map::RawEntryMut;
use rustc_hash::{FxBuildHasher, FxHasher};

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
    counts: HashMap<RawStackKey, u64, FxBuildHasher>,
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
        self.add_vec(pid, callchain.into_iter().collect(), count);
    }

    pub fn add_vec(&mut self, pid: Option<u32>, callchain: Vec<u64>, count: u64) {
        let key = RawStackKey { pid, callchain };
        *self.counts.entry(key).or_insert(0) += count;
    }

    pub fn add_slice(&mut self, pid: Option<u32>, callchain: &[u64], count: u64) {
        let hash = raw_stack_hash(pid, callchain);
        match self
            .counts
            .raw_entry_mut()
            .from_hash(hash, |key| key.pid == pid && key.callchain == callchain)
        {
            RawEntryMut::Occupied(mut entry) => {
                *entry.get_mut() += count;
            }
            RawEntryMut::Vacant(entry) => {
                entry.insert(
                    RawStackKey {
                        pid,
                        callchain: callchain.to_vec(),
                    },
                    count,
                );
            }
        }
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

fn raw_stack_hash(pid: Option<u32>, callchain: &[u64]) -> u64 {
    let mut hasher = FxHasher::default();
    pid.hash(&mut hasher);
    callchain.hash(&mut hasher);
    hasher.finish()
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

    #[test]
    fn accumulates_owned_raw_stack_vectors() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add_vec(Some(7), vec![0x1000, 0x2000], 1);
        accumulator.add_vec(Some(7), vec![0x1000, 0x2000], 2);

        let collapsed = accumulator.into_collapsed();

        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].callchain, vec![0x1000, 0x2000]);
        assert_eq!(collapsed[0].count, 3);
    }

    #[test]
    fn accumulates_borrowed_raw_stack_slices() {
        let mut accumulator = RawStackAccumulator::new();
        let stack = vec![0x1000, 0x2000];

        accumulator.add_slice(Some(7), &stack, 1);
        accumulator.add_slice(Some(7), &stack, 2);

        let collapsed = accumulator.into_collapsed();

        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].callchain, vec![0x1000, 0x2000]);
        assert_eq!(collapsed[0].count, 3);
    }
}
