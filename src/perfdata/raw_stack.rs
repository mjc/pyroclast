use std::cmp::Ordering;
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

#[derive(Clone, Copy, Debug)]
pub struct RawStackEntryRef<'a, T> {
    pid: Option<u32>,
    comm: Option<&'a str>,
    tail: Option<NodeId>,
    count: u64,
    nodes: &'a [StackNode<T>],
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

    #[must_use]
    pub fn sorted_entries(&self) -> Vec<RawStackEntryRef<'_, T>> {
        let mut entries = self
            .counts
            .iter()
            .map(|(key, &count)| RawStackEntryRef {
                pid: key.pid,
                comm: key
                    .comm
                    .and_then(|comm| self.comms.get(comm).map(String::as_str)),
                tail: key.tail,
                count,
                nodes: &self.nodes,
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.pid
                .cmp(&right.pid)
                .then_with(|| left.comm.cmp(&right.comm))
                .then_with(|| compare_callchain_tails(left.nodes, left.tail, right.tail))
        });
        entries
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
    rebuild_callchain_into(nodes, tail, &mut callchain);
    callchain
}

fn rebuild_callchain_into<T: Clone>(
    nodes: &[StackNode<T>],
    tail: Option<NodeId>,
    callchain: &mut Vec<T>,
) {
    callchain.clear();
    let mut current = tail;
    while let Some(node) = current {
        let entry = &nodes[node];
        callchain.push(entry.frame.clone());
        current = entry.parent;
    }
    callchain.reverse();
}

fn compare_callchain_tails<T: Ord>(
    nodes: &[StackNode<T>],
    left: Option<NodeId>,
    right: Option<NodeId>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => {
            if left == right {
                return Ordering::Equal;
            }
            let left_node = &nodes[left];
            let right_node = &nodes[right];
            compare_callchain_tails(nodes, left_node.parent, right_node.parent)
                .then_with(|| left_node.frame.cmp(&right_node.frame))
        }
    }
}

impl<'a, T> RawStackEntryRef<'a, T> {
    #[must_use]
    pub fn pid(self) -> Option<u32> {
        self.pid
    }

    #[must_use]
    pub fn comm(self) -> Option<&'a str> {
        self.comm
    }

    #[must_use]
    pub fn count(self) -> u64 {
        self.count
    }
}

impl<T> RawStackEntryRef<'_, T>
where
    T: Clone,
{
    pub fn callchain<'a>(&self, scratch: &'a mut Vec<T>) -> &'a [T] {
        rebuild_callchain_into(self.nodes, self.tail, scratch);
        scratch
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

    #[test]
    fn sorted_entries_follow_pid_comm_and_callchain_order() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add_slice_with_comm(Some(8), Some("beta".to_string()), &[2, 1], 3);
        accumulator.add_slice_with_comm(Some(7), Some("alpha".to_string()), &[1, 2], 1);
        accumulator.add_slice_with_comm(Some(7), Some("alpha".to_string()), &[1, 1], 2);

        let entries = accumulator.sorted_entries();
        let mut scratch = Vec::new();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].pid(), Some(7));
        assert_eq!(entries[0].comm(), Some("alpha"));
        assert_eq!(entries[0].count(), 2);
        assert_eq!(entries[0].callchain(&mut scratch), [1, 1]);

        assert_eq!(entries[1].pid(), Some(7));
        assert_eq!(entries[1].comm(), Some("alpha"));
        assert_eq!(entries[1].count(), 1);
        assert_eq!(entries[1].callchain(&mut scratch), [1, 2]);

        assert_eq!(entries[2].pid(), Some(8));
        assert_eq!(entries[2].comm(), Some("beta"));
        assert_eq!(entries[2].count(), 3);
        assert_eq!(entries[2].callchain(&mut scratch), [2, 1]);
    }
}
