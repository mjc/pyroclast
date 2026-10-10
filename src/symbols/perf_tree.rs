// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
use std::fmt::Write;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Color {
    Red,
    Black,
}

#[derive(Clone, Copy, Debug)]
struct Node {
    start: u64,
    parent: Option<usize>,
    left: Option<usize>,
    right: Option<usize>,
    color: Color,
}

/// Index-backed Linux-perf-compatible tree for original symbol-candidate IDs.
///
/// Insertion sends equal starts right before balancing, as perf's
/// `symbols__insert` does. Rotations preserve the resulting in-order sequence
/// and are kept compatible with Linux's `rb_insert_color`/`rb_erase` behavior
/// because `symbols__find` returns the first containing node on its search path.
/// Reference: Linux 7.2.9 `tools/perf/util/symbol.c` and `tools/lib/rbtree.c`.
pub(super) struct PerfSymbolTree {
    nodes: Vec<Option<Node>>,
    root: Option<usize>,
}

impl PerfSymbolTree {
    pub(super) fn new(candidate_count: usize) -> Self {
        Self {
            nodes: vec![None; candidate_count],
            root: None,
        }
    }

    /// Inserts a candidate under its stable original index; returns false if occupied.
    pub(super) fn insert(&mut self, symbol_index: usize, start: u64) -> bool {
        if symbol_index >= self.nodes.len() {
            return false;
        }
        if self.nodes[symbol_index].is_some() {
            return false;
        }

        let mut parent = None;
        let mut cursor = self.root;
        while let Some(index) = cursor {
            parent = Some(index);
            let node = self.node(index);
            cursor = if start < node.start {
                node.left
            } else {
                node.right
            };
        }

        self.nodes[symbol_index] = Some(Node {
            start,
            parent,
            left: None,
            right: None,
            color: Color::Red,
        });
        if let Some(parent) = parent {
            if start < self.node(parent).start {
                self.node_mut(parent).left = Some(symbol_index);
            } else {
                self.node_mut(parent).right = Some(symbol_index);
            }
        } else {
            self.root = Some(symbol_index);
        }

        self.insert_fixup(symbol_index);
        true
    }

    /// Removes exactly this candidate ID, preserving all other IDs and links.
    pub(super) fn remove(&mut self, symbol_index: usize) -> bool {
        if self.node_opt(symbol_index).is_none() {
            return false;
        }

        let mut removed_color = self.node(symbol_index).color;
        let replacement;
        let replacement_parent;
        let node = self.node(symbol_index);

        match (node.left, node.right) {
            (None, right) => {
                replacement = right;
                replacement_parent = node.parent;
                self.transplant(symbol_index, replacement);
            }
            (Some(left), None) => {
                replacement = Some(left);
                replacement_parent = node.parent;
                self.transplant(symbol_index, replacement);
            }
            (Some(left), Some(right)) => {
                let successor = self.minimum(right);
                removed_color = self.node(successor).color;
                replacement = self.node(successor).right;

                if self.node(successor).parent == Some(symbol_index) {
                    replacement_parent = Some(successor);
                    if let Some(replacement) = replacement {
                        self.node_mut(replacement).parent = Some(successor);
                    }
                } else {
                    let successor_parent = self.node(successor).parent;
                    replacement_parent = successor_parent;
                    self.transplant(successor, replacement);
                    self.node_mut(successor).right = Some(right);
                    self.node_mut(right).parent = Some(successor);
                }

                self.transplant(symbol_index, Some(successor));
                self.node_mut(successor).left = Some(left);
                self.node_mut(left).parent = Some(successor);
                self.node_mut(successor).color = node.color;
            }
        }

        self.nodes[symbol_index] = None;
        if removed_color == Color::Black {
            self.erase_fixup(replacement, replacement_parent);
        }
        true
    }

    pub(super) fn root_index(&self) -> Option<usize> {
        self.root
    }

    #[cfg(test)]
    pub(super) fn symbol_index(&self, node_index: usize) -> Option<usize> {
        self.node_opt(node_index).map(|_| node_index)
    }

    pub(super) fn children(&self, node_index: usize) -> Option<(Option<usize>, Option<usize>)> {
        self.node_opt(node_index)
            .map(|node| (node.left, node.right))
    }

    pub(super) fn indices_in_order(&self) -> Vec<usize> {
        let mut indices = Vec::new();
        let mut cursor = self.root;
        let mut stack = Vec::new();
        while cursor.is_some() || !stack.is_empty() {
            while let Some(index) = cursor {
                stack.push(index);
                cursor = self.node(index).left;
            }
            let index = stack.pop().expect("nonempty traversal stack");
            indices.push(index);
            cursor = self.node(index).right;
        }
        indices
    }

    /// Mirrors perf's `symbols__find`: follow the tree and return the first hit.
    pub(super) fn lookup(
        &self,
        address: u64,
        mut end_for: impl FnMut(usize) -> u64,
    ) -> Option<usize> {
        let mut cursor = self.root;
        while let Some(index) = cursor {
            let node = self.node(index);
            if address < node.start {
                cursor = node.left;
            } else {
                let end = end_for(index);
                if end == node.start && address == node.start {
                    return Some(index);
                }
                if address >= end {
                    cursor = node.right;
                } else {
                    return Some(index);
                }
            }
        }
        None
    }

    fn node_opt(&self, index: usize) -> Option<Node> {
        self.nodes.get(index).copied().flatten()
    }

    fn node(&self, index: usize) -> Node {
        self.node_opt(index).expect("active tree node")
    }

    fn node_mut(&mut self, index: usize) -> &mut Node {
        self.nodes[index].as_mut().expect("active tree node")
    }

    fn color(&self, index: Option<usize>) -> Color {
        index.map_or(Color::Black, |index| self.node(index).color)
    }

    fn set_color(&mut self, index: Option<usize>, color: Color) {
        if let Some(index) = index {
            self.node_mut(index).color = color;
        }
    }

    fn parent(&self, index: Option<usize>) -> Option<usize> {
        index.and_then(|index| self.node(index).parent)
    }

    fn minimum(&self, mut index: usize) -> usize {
        while let Some(left) = self.node(index).left {
            index = left;
        }
        index
    }

    fn transplant(&mut self, old: usize, new: Option<usize>) {
        let parent = self.node(old).parent;
        if let Some(parent) = parent {
            if self.node(parent).left == Some(old) {
                self.node_mut(parent).left = new;
            } else {
                self.node_mut(parent).right = new;
            }
        } else {
            self.root = new;
        }
        if let Some(new) = new {
            self.node_mut(new).parent = parent;
        }
    }

    fn rotate_left(&mut self, pivot: usize) {
        let top = self.node(pivot).right.expect("left rotation child");
        let middle = self.node(top).left;
        self.node_mut(pivot).right = middle;
        if let Some(middle) = middle {
            self.node_mut(middle).parent = Some(pivot);
        }
        self.replace_at_parent(pivot, top);
        self.node_mut(top).left = Some(pivot);
        self.node_mut(pivot).parent = Some(top);
    }

    fn rotate_right(&mut self, pivot: usize) {
        let top = self.node(pivot).left.expect("right rotation child");
        let middle = self.node(top).right;
        self.node_mut(pivot).left = middle;
        if let Some(middle) = middle {
            self.node_mut(middle).parent = Some(pivot);
        }
        self.replace_at_parent(pivot, top);
        self.node_mut(top).right = Some(pivot);
        self.node_mut(pivot).parent = Some(top);
    }

    fn replace_at_parent(&mut self, old: usize, new: usize) {
        let parent = self.node(old).parent;
        if let Some(parent) = parent {
            if self.node(parent).left == Some(old) {
                self.node_mut(parent).left = Some(new);
            } else {
                self.node_mut(parent).right = Some(new);
            }
        } else {
            self.root = Some(new);
        }
        self.node_mut(new).parent = parent;
    }

    fn insert_fixup(&mut self, mut node: usize) {
        while self.color(self.parent(Some(node))) == Color::Red {
            let parent = self.parent(Some(node)).expect("red parent");
            let grandparent = self.parent(Some(parent)).expect("red parent has parent");
            if self.node(grandparent).left == Some(parent) {
                let uncle = self.node(grandparent).right;
                if self.color(uncle) == Color::Red {
                    self.set_color(Some(parent), Color::Black);
                    self.set_color(uncle, Color::Black);
                    self.set_color(Some(grandparent), Color::Red);
                    node = grandparent;
                } else {
                    if self.node(parent).right == Some(node) {
                        node = parent;
                        self.rotate_left(node);
                    }
                    let parent = self.parent(Some(node)).expect("rotated parent");
                    let grandparent = self.parent(Some(parent)).expect("rotated grandparent");
                    self.set_color(Some(parent), Color::Black);
                    self.set_color(Some(grandparent), Color::Red);
                    self.rotate_right(grandparent);
                }
            } else {
                let uncle = self.node(grandparent).left;
                if self.color(uncle) == Color::Red {
                    self.set_color(Some(parent), Color::Black);
                    self.set_color(uncle, Color::Black);
                    self.set_color(Some(grandparent), Color::Red);
                    node = grandparent;
                } else {
                    if self.node(parent).left == Some(node) {
                        node = parent;
                        self.rotate_right(node);
                    }
                    let parent = self.parent(Some(node)).expect("rotated parent");
                    let grandparent = self.parent(Some(parent)).expect("rotated grandparent");
                    self.set_color(Some(parent), Color::Black);
                    self.set_color(Some(grandparent), Color::Red);
                    self.rotate_left(grandparent);
                }
            }
        }
        self.set_color(self.root, Color::Black);
    }

    fn erase_fixup(&mut self, mut node: Option<usize>, mut parent: Option<usize>) {
        while node != self.root && self.color(node) == Color::Black {
            let Some(parent_index) = parent else {
                break;
            };
            if node == self.node(parent_index).left {
                let mut sibling = self.node(parent_index).right;
                if self.color(sibling) == Color::Red {
                    self.set_color(sibling, Color::Black);
                    self.set_color(Some(parent_index), Color::Red);
                    self.rotate_left(parent_index);
                    sibling = self.node(parent_index).right;
                }
                let sibling_left = sibling.and_then(|index| self.node(index).left);
                let sibling_right = sibling.and_then(|index| self.node(index).right);
                if self.color(sibling_left) == Color::Black
                    && self.color(sibling_right) == Color::Black
                {
                    self.set_color(sibling, Color::Red);
                    node = Some(parent_index);
                    parent = self.parent(node);
                } else {
                    if self.color(sibling_right) == Color::Black {
                        self.set_color(sibling_left, Color::Black);
                        self.set_color(sibling, Color::Red);
                        if let Some(sibling) = sibling {
                            self.rotate_right(sibling);
                        }
                        sibling = self.node(parent_index).right;
                    }
                    self.set_color(sibling, self.node(parent_index).color);
                    self.set_color(Some(parent_index), Color::Black);
                    let sibling_right = sibling.and_then(|index| self.node(index).right);
                    self.set_color(sibling_right, Color::Black);
                    self.rotate_left(parent_index);
                    node = self.root;
                    parent = None;
                }
            } else {
                let mut sibling = self.node(parent_index).left;
                if self.color(sibling) == Color::Red {
                    self.set_color(sibling, Color::Black);
                    self.set_color(Some(parent_index), Color::Red);
                    self.rotate_right(parent_index);
                    sibling = self.node(parent_index).left;
                }
                let sibling_right = sibling.and_then(|index| self.node(index).right);
                let sibling_left = sibling.and_then(|index| self.node(index).left);
                if self.color(sibling_right) == Color::Black
                    && self.color(sibling_left) == Color::Black
                {
                    self.set_color(sibling, Color::Red);
                    node = Some(parent_index);
                    parent = self.parent(node);
                } else {
                    if self.color(sibling_left) == Color::Black {
                        self.set_color(sibling_right, Color::Black);
                        self.set_color(sibling, Color::Red);
                        if let Some(sibling) = sibling {
                            self.rotate_left(sibling);
                        }
                        sibling = self.node(parent_index).left;
                    }
                    self.set_color(sibling, self.node(parent_index).color);
                    self.set_color(Some(parent_index), Color::Black);
                    let sibling_left = sibling.and_then(|index| self.node(index).left);
                    self.set_color(sibling_left, Color::Black);
                    self.rotate_right(parent_index);
                    node = self.root;
                    parent = None;
                }
            }
        }
        self.set_color(node, Color::Black);
    }

    #[cfg(test)]
    fn shape(&self) -> String {
        fn write_node(tree: &PerfSymbolTree, index: Option<usize>, output: &mut String) {
            let Some(index) = index else {
                output.push('.');
                return;
            };
            let node = tree.node(index);
            let color = if node.color == Color::Red { 'R' } else { 'B' };
            write!(output, "{index}{color}(").expect("write to String");
            write_node(tree, node.left, output);
            output.push(',');
            write_node(tree, node.right, output);
            output.push(')');
        }

        let mut output = String::new();
        write_node(self, self.root, &mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::PerfSymbolTree;

    fn assert_native_trace(
        inserts: &[(usize, u64)],
        removals: &[usize],
        expected: &[&str],
    ) -> PerfSymbolTree {
        let candidate_count = inserts
            .iter()
            .map(|(index, _)| index + 1)
            .max()
            .unwrap_or(0);
        let mut tree = PerfSymbolTree::new(candidate_count);
        let mut state = 0;
        for &(index, start) in inserts {
            assert!(tree.insert(index, start));
            assert_eq!(tree.shape(), expected[state]);
            state += 1;
        }
        for &index in removals {
            assert!(tree.remove(index));
            assert_eq!(tree.shape(), expected[state]);
            state += 1;
        }
        assert_eq!(state, expected.len());
        tree
    }

    fn assert_invariants(tree: &PerfSymbolTree, active: &[bool]) {
        fn visit(
            tree: &PerfSymbolTree,
            index: Option<usize>,
            parent: Option<usize>,
            seen: &mut [bool],
        ) -> usize {
            let Some(index) = index else {
                return 1;
            };
            assert!(index < seen.len());
            assert!(!seen[index], "node visited more than once: {index}");
            seen[index] = true;
            let node = tree.node(index);
            assert_eq!(node.parent, parent);
            let left_black_height = visit(tree, node.left, Some(index), seen);
            let right_black_height = visit(tree, node.right, Some(index), seen);
            assert_eq!(left_black_height, right_black_height);
            if node.color == super::Color::Red {
                assert_eq!(tree.color(node.left), super::Color::Black);
                assert_eq!(tree.color(node.right), super::Color::Black);
            }
            left_black_height + usize::from(node.color == super::Color::Black)
        }

        assert!(tree.nodes.len() <= active.len());
        let mut seen = vec![false; active.len()];
        if let Some(root) = tree.root {
            assert_eq!(tree.node(root).parent, None);
            assert_eq!(tree.node(root).color, super::Color::Black);
            visit(tree, Some(root), None, &mut seen);
        }
        assert_eq!(seen, active);
        for (index, &is_active) in active.iter().enumerate() {
            assert_eq!(tree.node_opt(index).is_some(), is_active);
        }

        let ordered = tree.indices_in_order();
        assert!(
            ordered
                .windows(2)
                .all(|pair| tree.node(pair[0]).start <= tree.node(pair[1]).start)
        );
    }

    #[test]
    fn matches_linux_shape_for_sorted_insertions_and_removals() {
        let inserts = (0..=8)
            .map(|index| (index, index as u64 * 10))
            .collect::<Vec<_>>();
        let tree = assert_native_trace(
            &inserts,
            &[4, 0, 8, 3, 5],
            &[
                "0B(.,.)",
                "0B(.,1R(.,.))",
                "1B(0R(.,.),2R(.,.))",
                "1B(0B(.,.),2B(.,3R(.,.)))",
                "1B(0B(.,.),3B(2R(.,.),4R(.,.)))",
                "1B(0B(.,.),3R(2B(.,.),4B(.,5R(.,.))))",
                "1B(0B(.,.),3R(2B(.,.),5B(4R(.,.),6R(.,.))))",
                "3B(1R(0B(.,.),2B(.,.)),5R(4B(.,.),6B(.,7R(.,.))))",
                "3B(1R(0B(.,.),2B(.,.)),5R(4B(.,.),7B(6R(.,.),8R(.,.))))",
                "3B(1R(0B(.,.),2B(.,.)),7R(5B(.,6R(.,.)),8B(.,.)))",
                "3B(1B(.,2R(.,.)),7R(5B(.,6R(.,.)),8B(.,.)))",
                "3B(1B(.,2R(.,.)),6R(5B(.,.),7B(.,.)))",
                "5B(1B(.,2R(.,.)),6B(.,7R(.,.)))",
                "6B(1B(.,2R(.,.)),7B(.,.))",
            ],
        );
        assert_eq!(tree.shape(), "6B(1B(.,2R(.,.)),7B(.,.))");
    }

    #[test]
    fn matches_linux_shape_for_reverse_insertions_and_removals() {
        let inserts = (0..=8)
            .rev()
            .map(|index| (index, index as u64 * 10))
            .collect::<Vec<_>>();
        let tree = assert_native_trace(
            &inserts,
            &[5, 0, 7],
            &[
                "8B(.,.)",
                "8B(7R(.,.),.)",
                "7B(6R(.,.),8R(.,.))",
                "7B(6B(5R(.,.),.),8B(.,.))",
                "7B(5B(4R(.,.),6R(.,.)),8B(.,.))",
                "7B(5R(4B(3R(.,.),.),6B(.,.)),8B(.,.))",
                "7B(5R(3B(2R(.,.),4R(.,.)),6B(.,.)),8B(.,.))",
                "5B(3R(2B(1R(.,.),.),4B(.,.)),7R(6B(.,.),8B(.,.)))",
                "5B(3R(1B(0R(.,.),2R(.,.)),4B(.,.)),7R(6B(.,.),8B(.,.)))",
                "6B(3R(1B(0R(.,.),2R(.,.)),4B(.,.)),7B(.,8R(.,.)))",
                "6B(3R(1B(.,2R(.,.)),4B(.,.)),7B(.,8R(.,.)))",
                "6B(3R(1B(.,2R(.,.)),4B(.,.)),8B(.,.))",
            ],
        );
        assert_eq!(tree.shape(), "6B(3R(1B(.,2R(.,.)),4B(.,.)),8B(.,.))");
    }

    #[test]
    fn matches_linux_shape_for_equal_starts_and_removals() {
        let inserts = (0..10).map(|index| (index, 7)).collect::<Vec<_>>();
        let tree = assert_native_trace(
            &inserts,
            &[4, 7, 1, 8],
            &[
                "0B(.,.)",
                "0B(.,1R(.,.))",
                "1B(0R(.,.),2R(.,.))",
                "1B(0B(.,.),2B(.,3R(.,.)))",
                "1B(0B(.,.),3B(2R(.,.),4R(.,.)))",
                "1B(0B(.,.),3R(2B(.,.),4B(.,5R(.,.))))",
                "1B(0B(.,.),3R(2B(.,.),5B(4R(.,.),6R(.,.))))",
                "3B(1R(0B(.,.),2B(.,.)),5R(4B(.,.),6B(.,7R(.,.))))",
                "3B(1R(0B(.,.),2B(.,.)),5R(4B(.,.),7B(6R(.,.),8R(.,.))))",
                "3B(1B(0B(.,.),2B(.,.)),5B(4B(.,.),7R(6B(.,.),8B(.,9R(.,.)))))",
                "3B(1B(0B(.,.),2B(.,.)),7B(5B(.,6R(.,.)),8B(.,9R(.,.))))",
                "3B(1B(0B(.,.),2B(.,.)),8B(5B(.,6R(.,.)),9B(.,.)))",
                "3B(2B(0R(.,.),.),8R(5B(.,6R(.,.)),9B(.,.)))",
                "3B(2B(0R(.,.),.),6R(5B(.,.),9B(.,.)))",
            ],
        );
        assert_eq!(tree.shape(), "3B(2B(0R(.,.),.),6R(5B(.,.),9B(.,.)))");
        assert_eq!(tree.indices_in_order(), [0, 2, 3, 5, 6, 9]);
    }

    #[test]
    fn matches_linux_shape_for_mixed_keys_and_successor_deletions() {
        let inserts = [
            (4, 40),
            (1, 10),
            (7, 70),
            (0, 0),
            (2, 20),
            (6, 60),
            (8, 80),
            (5, 50),
            (3, 30),
            (9, 20),
            (10, 50),
        ];
        let tree = assert_native_trace(
            &inserts,
            &[4, 6, 1, 8, 9],
            &[
                "4B(.,.)",
                "4B(1R(.,.),.)",
                "4B(1R(.,.),7R(.,.))",
                "4B(1B(0R(.,.),.),7B(.,.))",
                "4B(1B(0R(.,.),2R(.,.)),7B(.,.))",
                "4B(1B(0R(.,.),2R(.,.)),7B(6R(.,.),.))",
                "4B(1B(0R(.,.),2R(.,.)),7B(6R(.,.),8R(.,.)))",
                "4B(1B(0R(.,.),2R(.,.)),7R(6B(5R(.,.),.),8B(.,.)))",
                "4B(1R(0B(.,.),2B(.,3R(.,.))),7R(6B(5R(.,.),.),8B(.,.)))",
                "4B(1R(0B(.,.),9B(2R(.,.),3R(.,.))),7R(6B(5R(.,.),.),8B(.,.)))",
                "4B(1R(0B(.,.),9B(2R(.,.),3R(.,.))),7R(10B(5R(.,.),6R(.,.)),8B(.,.)))",
                "5B(1R(0B(.,.),9B(2R(.,.),3R(.,.))),7R(10B(.,6R(.,.)),8B(.,.)))",
                "5B(1R(0B(.,.),9B(2R(.,.),3R(.,.))),7R(10B(.,.),8B(.,.)))",
                "5B(2R(0B(.,.),9B(.,3R(.,.))),7R(10B(.,.),8B(.,.)))",
                "5B(2R(0B(.,.),9B(.,3R(.,.))),7B(10R(.,.),.))",
                "5B(2R(0B(.,.),3B(.,.)),7B(10R(.,.),.))",
            ],
        );
        assert_eq!(tree.shape(), "5B(2R(0B(.,.),3B(.,.)),7B(10R(.,.),.))");
    }

    #[test]
    fn checks_native_topology_checkpoints_and_rb_invariants_over_reinsertions() {
        enum Operation {
            Insert(usize, u64),
            Remove(usize),
        }

        let mut operations = Vec::with_capacity(320);
        for step in 0..80 {
            let index = (step * 37) % 80;
            let start = (step * 29 + (step / 7) * 3) % 13;
            operations.push(Operation::Insert(index, start as u64));
        }
        for step in 0..80 {
            operations.push(Operation::Remove((step * 53) % 80));
        }
        for step in 0..80 {
            let index = 79 - step;
            let start = (step * 11 + (step / 5) * 7 + 4) % 13;
            operations.push(Operation::Insert(index, start as u64));
        }
        for step in 0..80 {
            operations.push(Operation::Remove((step * 29) % 80));
        }

        let checkpoints = [
            (
                80,
                "62B(25B(56R(44B(0B(.,.),22R(51B(.,.),29B(.,73R(.,.)))),27B(20B(.,.),78B(34R(.,.),5R(.,.)))),8R(37B(3R(32B(.,.),54B(10R(.,.),61R(.,.))),1B(.,.)),13B(59B(15R(.,.),66R(.,.)),71R(64B(.,.),42B(35R(.,.),49R(.,.)))))),31R(57B(74R(76B(69B(.,.),47B(40R(.,.),18R(.,.))),52B(45B(.,.),23R(16B(.,.),50B(30R(.,.),.)))),26B(28R(21B(.,.),79B(.,6R(.,.))),77R(33B(.,.),11B(4R(.,.),55R(.,.))))),19B(7R(2B(38B(.,.),60B(9R(.,.),67R(.,.))),58B(14B(.,.),72R(65B(.,.),36B(.,43R(.,.))))),68R(70B(63B(.,.),48B(41R(.,.),12R(.,.))),39B(75B(.,.),53R(46B(.,.),17B(.,24R(.,.))))))))",
            ),
            (
                120,
                "62B(32B(56B(29B(.,.),34R(27B(.,.),5B(.,.))),8R(37B(54R(3B(.,10R(.,.)),61B(.,.)),1B(.,.)),13B(59B(.,66R(.,.)),35B(64R(.,.),.)))),31R(33B(57B(40B(.,30R(.,.)),28B(.,6R(.,.))),11B(4B(.,.),55B(.,.))),7B(2B(38B(.,.),60B(9R(.,.),.)),63B(65R(58B(.,.),36B(.,.)),12B(.,39R(.,.))))))",
            ),
            (160, "."),
            (161, "79B(.,.)"),
            (
                200,
                "70B(78R(60B(77B(.,.),74R(53B(.,.),57B(.,40R(.,.)))),79B(65R(61B(.,54R(.,.)),58B(.,41R(.,.))),66R(62B(.,45R(.,.)),59B(.,42R(.,.))))),75R(71B(67R(63B(.,46R(.,.)),50B(.,43R(.,.))),64B(.,47R(.,.))),76B(72R(51B(68R(.,.),44R(.,.)),55B(.,48R(.,.))),73R(69B(.,52R(.,.)),56B(.,49R(.,.))))))",
            ),
            (
                240,
                "70B(78B(74R(60B(77B(.,.),36R(53B(.,.),29B(.,12R(.,.)))),40B(57B(.,.),16B(33R(.,.),9R(.,.)))),79R(65B(54R(61B(.,.),20B(37R(.,.),13R(.,.))),41R(58B(.,.),17B(34R(.,.),0R(.,.)))),66B(45R(62B(.,.),21B(38R(.,.),14R(.,.))),42R(59B(.,.),18B(25R(.,.),1R(.,.)))))),75R(71B(67B(46R(63B(.,.),22B(39R(.,.),5R(.,.))),43R(50B(.,.),19B(26R(.,.),2R(.,.)))),47B(64B(.,.),23B(30R(.,.),6R(.,.)))),76B(72R(51B(68B(.,.),27R(44B(.,.),10B(.,3R(.,.)))),48B(55B(.,.),24B(31R(.,.),7R(.,.)))),73R(52B(69B(.,.),28R(35B(.,.),11B(.,4R(.,.)))),49B(56B(.,.),15B(32R(.,.),8R(.,.)))))))",
            ),
            (
                241,
                "70B(78B(74R(60B(77B(.,.),36R(53B(.,.),29B(.,12R(.,.)))),40B(57B(.,.),16B(33R(.,.),9R(.,.)))),79R(65B(54R(61B(.,.),20B(37R(.,.),13R(.,.))),41R(58B(.,.),17B(34R(.,.),.))),66B(45R(62B(.,.),21B(38R(.,.),14R(.,.))),42R(59B(.,.),18B(25R(.,.),1R(.,.)))))),75R(71B(67B(46R(63B(.,.),22B(39R(.,.),5R(.,.))),43R(50B(.,.),19B(26R(.,.),2R(.,.)))),47B(64B(.,.),23B(30R(.,.),6R(.,.)))),76B(72R(51B(68B(.,.),27R(44B(.,.),10B(.,3R(.,.)))),48B(55B(.,.),24B(31R(.,.),7R(.,.)))),73R(52B(69B(.,.),28R(35B(.,.),11B(.,4R(.,.)))),49B(56B(.,.),15B(32R(.,.),8R(.,.)))))))",
            ),
            (
                280,
                "46B(61B(74B(60B(.,53R(.,.)),16R(40B(.,.),9B(.,.))),45R(37B(54B(.,.),17B(.,.)),66B(38B(.,.),25R(59B(.,.),18B(.,1R(.,.)))))),75R(2B(22B(39B(.,.),67B(.,.)),30B(47B(.,.),23B(.,.))),76B(10R(51B(68B(.,.),44B(.,.)),31B(3B(.,.),24B(.,.))),73B(52B(69R(.,.),.),15R(32B(.,.),8B(.,.))))))",
            ),
            (320, "."),
        ];

        let mut tree = PerfSymbolTree::new(80);
        let mut active = vec![false; 80];
        let mut checkpoint_index = 0;
        let mut two_child_removals = 0;
        for (position, operation) in operations.into_iter().enumerate() {
            match operation {
                Operation::Insert(index, start) => {
                    assert!(!active[index]);
                    assert!(tree.insert(index, start));
                    active[index] = true;
                }
                Operation::Remove(index) => {
                    assert!(active[index]);
                    let (left, right) = tree.children(index).expect("active node");
                    two_child_removals += usize::from(left.is_some() && right.is_some());
                    assert!(tree.remove(index));
                    active[index] = false;
                }
            }

            assert_invariants(&tree, &active);
            let state = position + 1;
            if state == checkpoints[checkpoint_index].0 {
                assert_eq!(tree.shape(), checkpoints[checkpoint_index].1);
                checkpoint_index += 1;
            }
        }
        assert_eq!(checkpoint_index, checkpoints.len());
        assert!(two_child_removals > 20);
    }

    #[test]
    fn exposes_remapped_identity_and_native_path_lookup() {
        let mut tree = PerfSymbolTree::new(12);
        for (index, start) in [(8, 10), (3, 20), (11, 30), (1, 40), (9, 50)] {
            assert!(tree.insert(index, start));
        }
        assert!(!tree.insert(3, 99));
        assert!(!tree.insert(usize::MAX, 0));
        assert!(!tree.insert(usize::MAX - 1, 0));
        assert!(!tree.insert(12, 0));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tree.insert(usize::MAX - 1, 0)
        }));
        assert!(matches!(result, Ok(false)));
        let root = tree.root_index().expect("nonempty tree");
        assert_eq!(tree.symbol_index(root), Some(root));
        assert!(tree.children(root).is_some());
        assert_eq!(tree.indices_in_order(), [8, 3, 11, 1, 9]);

        let ends = [(8, 80), (3, 90), (11, 100), (1, 110), (9, 120)]
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(tree.lookup(55, |index| ends[&index]), Some(root));
        assert_eq!(tree.lookup(10, |index| ends[&index]), Some(8));
        assert_eq!(tree.lookup(121, |index| ends[&index]), None);
        assert!(tree.remove(3));
        assert!(!tree.remove(3));
        assert!(tree.insert(3, 20));

        let empty = PerfSymbolTree::new(0);
        assert_eq!(
            empty.lookup(0, |_| panic!("empty lookup called end closure")),
            None
        );

        let mut zero_length = PerfSymbolTree::new(1);
        assert!(zero_length.insert(0, 0));
        assert_eq!(zero_length.lookup(0, |_| 0), Some(0));
        assert_eq!(zero_length.lookup(1, |_| 0), None);

        let mut exact_end = PerfSymbolTree::new(1);
        assert!(exact_end.insert(0, 1));
        assert_eq!(exact_end.lookup(2, |_| 3), Some(0));
        assert_eq!(exact_end.lookup(3, |_| 3), None);

        let mut overlapping = PerfSymbolTree::new(3);
        assert!(overlapping.insert(0, 0));
        assert!(overlapping.insert(1, 10));
        assert!(overlapping.insert(2, 20));
        let hit = overlapping
            .lookup(25, |index| [(0, 30), (1, 40), (2, 50)][index].1)
            .unwrap();
        assert_eq!(overlapping.root_index(), Some(1));
        assert_eq!(hit, 1);
        assert_ne!(hit, 2, "nearest-start candidate is not the native path hit");
    }
}
