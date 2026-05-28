use std::hash::Hash;

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;

type CommId = usize;
type NodeId = usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollapsedRawStack<T = u64> {
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub callchain: Vec<T>,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RawStackKey {
    pid: Option<u32>,
    comm: Option<CommId>,
    tail: Option<NodeId>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StackNodeKey<T> {
    parent: Option<NodeId>,
    frame: T,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StackNode<T> {
    parent: Option<NodeId>,
    frame: T,
}

#[derive(Debug)]
pub struct RawStackAccumulator<T = u64> {
    counts: HashMap<RawStackKey, u64, FxBuildHasher>,
    nodes: Vec<StackNode<T>>,
    node_ids: HashMap<StackNodeKey<T>, NodeId, FxBuildHasher>,
    comms: Vec<String>,
    comm_ids: HashMap<String, CommId, FxBuildHasher>,
}

impl<T> Default for RawStackAccumulator<T> {
    fn default() -> Self {
        Self {
            counts: HashMap::default(),
            nodes: Vec::new(),
            node_ids: HashMap::default(),
            comms: Vec::new(),
            comm_ids: HashMap::default(),
        }
    }
}

impl<T> RawStackAccumulator<T>
where
    T: Clone + Eq + Hash + Ord,
{
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add<I>(&mut self, pid: Option<u32>, callchain: I, count: u64)
    where
        I: IntoIterator<Item = T>,
    {
        self.add_vec(pid, callchain.into_iter().collect(), count);
    }

    pub fn add_vec(&mut self, pid: Option<u32>, callchain: Vec<T>, count: u64) {
        self.add_vec_with_comm(pid, None, callchain, count);
    }

    pub fn add_vec_with_comm(
        &mut self,
        pid: Option<u32>,
        comm: Option<String>,
        callchain: Vec<T>,
        count: u64,
    ) {
        let comm = self.intern_comm(comm);
        let tail = self.intern_callchain(callchain);
        *self
            .counts
            .entry(RawStackKey { pid, comm, tail })
            .or_insert(0) += count;
    }

    pub fn add_slice(&mut self, pid: Option<u32>, callchain: &[T], count: u64) {
        self.add_slice_with_comm(pid, None, callchain, count);
    }

    pub fn add_slice_with_comm(
        &mut self,
        pid: Option<u32>,
        comm: Option<String>,
        callchain: &[T],
        count: u64,
    ) {
        let comm = self.intern_comm(comm);
        let tail = self.intern_callchain(callchain.iter().cloned());
        *self
            .counts
            .entry(RawStackKey { pid, comm, tail })
            .or_insert(0) += count;
    }

    #[must_use]
    pub fn into_collapsed(self) -> Vec<CollapsedRawStack<T>> {
        let Self {
            counts,
            nodes,
            node_ids: _,
            comms,
            comm_ids: _,
        } = self;
        let mut collapsed = counts
            .into_iter()
            .map(|(key, count)| CollapsedRawStack {
                pid: key.pid,
                comm: key.comm.and_then(|comm| comms.get(comm).cloned()),
                callchain: rebuild_callchain(&nodes, key.tail),
                count,
            })
            .collect::<Vec<_>>();
        collapsed.sort_by(|left, right| {
            left.pid
                .cmp(&right.pid)
                .then_with(|| left.comm.cmp(&right.comm))
                .then_with(|| left.callchain.cmp(&right.callchain))
        });
        collapsed
    }

    fn intern_comm(&mut self, comm: Option<String>) -> Option<CommId> {
        let comm = comm?;
        if let Some(&id) = self.comm_ids.get(comm.as_str()) {
            return Some(id);
        }
        let id = self.comms.len();
        self.comms.push(comm.clone());
        self.comm_ids.insert(comm, id);
        Some(id)
    }

    fn intern_callchain<I>(&mut self, callchain: I) -> Option<NodeId>
    where
        I: IntoIterator<Item = T>,
    {
        let mut tail = None;
        for frame in callchain {
            let key = StackNodeKey {
                parent: tail,
                frame: frame.clone(),
            };
            tail = Some(if let Some(&id) = self.node_ids.get(&key) {
                id
            } else {
                let id = self.nodes.len();
                self.nodes.push(StackNode {
                    parent: tail,
                    frame: frame.clone(),
                });
                self.node_ids.insert(key, id);
                id
            });
        }
        tail
    }

    #[cfg(test)]
    fn interned_node_count(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(test)]
    fn interned_comm_count(&self) -> usize {
        self.comms.len()
    }
}

fn rebuild_callchain<T: Clone>(nodes: &[StackNode<T>], tail: Option<NodeId>) -> Vec<T> {
    let mut callchain = Vec::new();
    let mut current = tail;
    while let Some(node) = current {
        let entry = &nodes[node];
        callchain.push(entry.frame.clone());
        current = entry.parent;
    }
    callchain.reverse();
    callchain
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

    #[test]
    fn shares_interned_prefix_nodes_between_distinct_stacks() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add_slice_with_comm(Some(7), Some("pyroclast".to_string()), &[1, 2, 3], 1);
        accumulator.add_slice_with_comm(Some(8), Some("pyroclast".to_string()), &[1, 2, 4], 1);

        assert_eq!(accumulator.interned_node_count(), 4);
        assert_eq!(accumulator.interned_comm_count(), 1);

        let collapsed = accumulator.into_collapsed();

        assert_eq!(collapsed.len(), 2);
        assert_eq!(collapsed[0].callchain, vec![1, 2, 3]);
        assert_eq!(collapsed[1].callchain, vec![1, 2, 4]);
    }

    #[test]
    fn keeps_prefix_stacks_distinct_from_longer_stacks() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add(Some(7), [1, 2], 2);
        accumulator.add(Some(7), [1, 2, 3], 1);

        assert_eq!(accumulator.interned_node_count(), 3);

        let collapsed = accumulator.into_collapsed();

        assert_eq!(collapsed.len(), 2);
        assert_eq!(collapsed[0].callchain, vec![1, 2]);
        assert_eq!(collapsed[0].count, 2);
        assert_eq!(collapsed[1].callchain, vec![1, 2, 3]);
        assert_eq!(collapsed[1].count, 1);
    }

    #[test]
    fn round_trips_empty_callchains() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add_vec_with_comm(Some(7), Some("pyroclast".to_string()), Vec::<u64>::new(), 5);

        let collapsed = accumulator.into_collapsed();

        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].pid, Some(7));
        assert_eq!(collapsed[0].comm.as_deref(), Some("pyroclast"));
        assert!(collapsed[0].callchain.is_empty());
        assert_eq!(collapsed[0].count, 5);
    }
}
