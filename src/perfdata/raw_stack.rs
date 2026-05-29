use std::hash::{BuildHasher, Hash, Hasher};

use hashbrown::{HashMap, HashTable};
use rustc_hash::FxBuildHasher;

type CommId = u64;
type NodeId = u64;
const RAW_STACK_GROWTH_MIN_CHUNK: usize = 1024;

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct StackNode<T> {
    parent: Option<NodeId>,
    frame: T,
}

#[derive(Debug)]
pub struct RawStackAccumulator<T = u64> {
    counts: HashMap<RawStackKey, u64, FxBuildHasher>,
    nodes: Vec<StackNode<T>>,
    node_ids: HashTable<NodeId>,
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

#[derive(Clone, Copy, Debug)]
pub struct RawStackFrameIter<'a, T> {
    nodes: &'a [StackNode<T>],
    current: Option<NodeId>,
}

impl<T> Default for RawStackAccumulator<T> {
    fn default() -> Self {
        Self {
            counts: HashMap::default(),
            nodes: Vec::new(),
            node_ids: HashTable::new(),
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
        self.reserve_counts_growth(1);
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
        self.reserve_counts_growth(1);
        *self
            .counts
            .entry(RawStackKey { pid, comm, tail })
            .or_insert(0) += count;
    }

    pub fn add_slice_with_borrowed_comm(
        &mut self,
        pid: Option<u32>,
        comm: Option<&str>,
        callchain: &[T],
        count: u64,
    ) {
        let comm = self.intern_comm_ref(comm);
        let tail = self.intern_callchain(callchain.iter().cloned());
        self.reserve_counts_growth(1);
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
                comm: key
                    .comm
                    .and_then(|comm| comms.get(node_index(comm)).cloned()),
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
    pub fn entries(&self) -> Vec<RawStackEntryRef<'_, T>> {
        self.counts
            .iter()
            .map(|(key, &count)| RawStackEntryRef {
                pid: key.pid,
                comm: key
                    .comm
                    .and_then(|comm| self.comms.get(node_index(comm)).map(String::as_str)),
                tail: key.tail,
                count,
                nodes: &self.nodes,
            })
            .collect()
    }

    #[must_use]
    pub fn sorted_entries(&self) -> Vec<RawStackEntryRef<'_, T>> {
        let mut entries = self.entries();
        entries.sort_by(|left, right| {
            left.pid
                .cmp(&right.pid)
                .then_with(|| left.comm.cmp(&right.comm))
                .then_with(|| left.tail.cmp(&right.tail))
        });
        entries
    }

    fn intern_comm(&mut self, comm: Option<String>) -> Option<CommId> {
        let comm = comm?;
        if let Some(&id) = self.comm_ids.get(comm.as_str()) {
            return Some(id);
        }
        let id = next_comm_id(self.comms.len());
        self.comms.push(comm.clone());
        self.comm_ids.insert(comm, id);
        Some(id)
    }

    fn intern_comm_ref(&mut self, comm: Option<&str>) -> Option<CommId> {
        let comm = comm?;
        if let Some(&id) = self.comm_ids.get(comm) {
            return Some(id);
        }
        let owned = comm.to_owned();
        let id = next_comm_id(self.comms.len());
        self.comms.push(owned.clone());
        self.comm_ids.insert(owned, id);
        Some(id)
    }

    fn intern_callchain<I>(&mut self, callchain: I) -> Option<NodeId>
    where
        I: IntoIterator<Item = T>,
    {
        let callchain = callchain.into_iter();
        let (lower_bound, upper_bound) = callchain.size_hint();
        self.reserve_node_growth(upper_bound.unwrap_or(lower_bound));
        let mut tail = None;
        for frame in callchain {
            let hash = node_key_hash(tail, &frame);
            tail = Some(
                if let Some(id) = {
                    let nodes = &self.nodes;
                    self.node_ids
                        .find(hash, |&id| node_matches(nodes, id, tail, &frame))
                        .copied()
                } {
                    id
                } else {
                    let id = next_node_id(self.nodes.len());
                    self.nodes.push(StackNode {
                        parent: tail,
                        frame,
                    });
                    let nodes = &self.nodes;
                    self.node_ids
                        .insert_unique(hash, id, |&id| interned_node_hash(nodes, id));
                    id
                },
            );
        }
        tail
    }

    fn reserve_counts_growth(&mut self, additional: usize) {
        if self.counts.capacity().saturating_sub(self.counts.len()) >= additional {
            return;
        }
        self.counts
            .reserve(growth_chunk(self.counts.len(), additional));
    }

    fn reserve_node_growth(&mut self, additional: usize) {
        if additional == 0 {
            return;
        }
        if self.nodes.capacity().saturating_sub(self.nodes.len()) < additional {
            self.nodes
                .reserve(growth_chunk(self.nodes.len(), additional));
        }
        if self.node_ids.capacity().saturating_sub(self.node_ids.len()) < additional {
            let nodes = &self.nodes;
            self.node_ids
                .reserve(growth_chunk(self.node_ids.len(), additional), |&id| {
                    interned_node_hash(nodes, id)
                });
        }
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
        let entry = &nodes[node_index(node)];
        callchain.push(entry.frame.clone());
        current = entry.parent;
    }
    callchain.reverse();
}

fn next_comm_id(len: usize) -> CommId {
    CommId::try_from(len).expect("raw stack comm ids exceeded u64::MAX")
}

fn next_node_id(len: usize) -> NodeId {
    NodeId::try_from(len).expect("raw stack node ids exceeded u64::MAX")
}

fn node_index(node: NodeId) -> usize {
    usize::try_from(node).expect("raw stack node id does not fit in usize")
}

fn growth_chunk(len: usize, additional: usize) -> usize {
    len.max(additional).max(RAW_STACK_GROWTH_MIN_CHUNK)
}

fn node_key_hash<T: Hash>(parent: Option<NodeId>, frame: &T) -> u64 {
    let mut hasher = FxBuildHasher.build_hasher();
    parent.hash(&mut hasher);
    frame.hash(&mut hasher);
    hasher.finish()
}

fn interned_node_hash<T: Hash>(nodes: &[StackNode<T>], id: NodeId) -> u64 {
    let entry = &nodes[node_index(id)];
    node_key_hash(entry.parent, &entry.frame)
}

fn node_matches<T: Eq>(
    nodes: &[StackNode<T>],
    id: NodeId,
    parent: Option<NodeId>,
    frame: &T,
) -> bool {
    let entry = &nodes[node_index(id)];
    entry.parent == parent && entry.frame == *frame
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

    #[must_use]
    pub fn frames_leaf_to_root(self) -> RawStackFrameIter<'a, T> {
        RawStackFrameIter {
            nodes: self.nodes,
            current: self.tail,
        }
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

impl<'a, T> Iterator for RawStackFrameIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.current?;
        let entry = &self.nodes[node_index(node)];
        self.current = entry.parent;
        Some(&entry.frame)
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
    fn reuses_interned_nodes_across_owned_and_borrowed_insert_paths() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add_vec(Some(7), vec![1, 2, 3], 1);
        accumulator.add_slice(Some(7), &[1, 2, 3], 2);

        assert_eq!(accumulator.interned_node_count(), 3);

        let collapsed = accumulator.into_collapsed();

        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].callchain, vec![1, 2, 3]);
        assert_eq!(collapsed[0].count, 3);
    }

    #[test]
    fn preserves_counts_across_large_table_growth() {
        let mut accumulator = RawStackAccumulator::new();

        for value in 0..2048_u64 {
            accumulator.add(Some(7), [value, value + 1], 1);
        }

        let collapsed = accumulator.into_collapsed();

        assert_eq!(collapsed.len(), 2048);
        assert_eq!(collapsed[0].callchain, vec![0, 1]);
        assert_eq!(collapsed[0].count, 1);
        assert_eq!(collapsed[2047].callchain, vec![2047, 2048]);
        assert_eq!(collapsed[2047].count, 1);
    }

    #[test]
    fn iterates_frames_leaf_to_root_without_rebuild_allocation() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add(Some(7), [1, 2, 3], 1);

        let entries = accumulator.sorted_entries();
        let frames = entries[0]
            .frames_leaf_to_root()
            .copied()
            .collect::<Vec<_>>();

        assert_eq!(frames, vec![3, 2, 1]);
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
    fn sorted_entries_follow_pid_and_comm_order() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add_slice_with_comm(Some(8), Some("beta".to_string()), &[2, 1], 3);
        accumulator.add_slice_with_comm(Some(7), Some("alpha".to_string()), &[1, 2], 1);
        accumulator.add_slice_with_comm(Some(7), Some("alpha".to_string()), &[1, 1], 2);

        let entries = accumulator.sorted_entries();
        let mut scratch = Vec::new();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].pid(), Some(7));
        assert_eq!(entries[0].comm(), Some("alpha"));
        assert_eq!(entries[1].pid(), Some(7));
        assert_eq!(entries[1].comm(), Some("alpha"));
        assert_eq!(entries[2].pid(), Some(8));
        assert_eq!(entries[2].comm(), Some("beta"));
        assert_eq!(entries[2].count(), 3);
        assert_eq!(entries[2].callchain(&mut scratch), [2, 1]);

        let mut alpha_callchains = [
            (
                entries[0].callchain(&mut scratch).to_vec(),
                entries[0].count(),
            ),
            (
                entries[1].callchain(&mut scratch).to_vec(),
                entries[1].count(),
            ),
        ];
        alpha_callchains.sort_unstable();
        assert_eq!(alpha_callchains, [(vec![1, 1], 2), (vec![1, 2], 1)]);
    }

    #[test]
    fn borrows_comm_names_without_reinterning_duplicates() {
        let mut accumulator = RawStackAccumulator::new();

        accumulator.add_slice_with_borrowed_comm(Some(7), Some("pyroclast"), &[1, 2, 3], 1);
        accumulator.add_slice_with_borrowed_comm(Some(8), Some("pyroclast"), &[1, 2, 4], 1);

        assert_eq!(accumulator.interned_comm_count(), 1);
    }
}
