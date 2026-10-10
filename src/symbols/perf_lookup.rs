// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::cmp::Ordering;
use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PerfSymbolLookupRecord {
    pub(super) candidate: usize,
    pub(super) start: u64,
    pub(super) end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PerfPltHeaderPhase {
    pub(super) candidate: usize,
    pub(super) remove_before_entries: bool,
}

#[derive(Default)]
pub(super) struct PerfSymbolLookupIndex {
    pub(super) records: Vec<PerfSymbolLookupRecord>,
    search_tree: Option<PerfObjectSearchTree>,
}

impl PerfSymbolLookupIndex {
    #[cfg(test)]
    pub(super) fn from_elf_tables(
        records: Vec<PerfSymbolLookupRecord>,
        tables: &[Range<usize>],
        synthetic: Range<usize>,
        candidates: &[super::PerfSymbolCandidate],
        fixup: bool,
    ) -> Self {
        Self::from_elf_tables_with_plt_header(records, tables, synthetic, candidates, fixup, None)
    }

    pub(super) fn from_elf_tables_with_plt_header(
        mut records: Vec<PerfSymbolLookupRecord>,
        tables: &[Range<usize>],
        synthetic: Range<usize>,
        candidates: &[super::PerfSymbolCandidate],
        fixup: bool,
        plt_header: Option<PerfPltHeaderPhase>,
    ) -> Self {
        let mut tree = super::perf_tree::PerfSymbolTree::new(records.len());
        for table in tables {
            for (record_id, record) in records.iter().enumerate() {
                if table.contains(&record.candidate) {
                    assert!(tree.insert(record_id, record.start));
                }
            }
            if fixup {
                Self::fixup_ends(&mut records, &tree);
                Self::remove_duplicates(&mut records, candidates, &mut tree);
            }
        }

        if let Some(phase) = plt_header {
            let header = records
                .iter()
                .position(|record| record.candidate == phase.candidate)
                .expect("PLT header has a raw lookup record");
            let start = records[header].start;
            if let Some(overlap) = tree.lookup(start, |id| records[id].end)
                && records[overlap].start < start
                && records[overlap].end > start
            {
                records[overlap].end = start;
            }
            assert!(tree.insert(header, start));
            if phase.remove_before_entries {
                assert!(tree.remove(header));
            }
        }

        for (record_id, record) in records.iter().copied().enumerate() {
            if synthetic.contains(&record.candidate) {
                if plt_header.is_some_and(|phase| phase.candidate == record.candidate) {
                    continue;
                }
                assert!(tree.insert(record_id, record.start));
            }
        }

        let active = tree.indices_in_order();
        let overlaps = active.windows(2).any(|pair| {
            let previous = records[pair[0]];
            let current = records[pair[1]];
            current.start < previous.end
                || (current.start == previous.start
                    && (current.end == current.start || previous.end == previous.start))
        });
        let search_tree =
            overlaps.then(|| PerfObjectSearchTree::from_tree(&tree, &active, records.len()));
        let records = active.into_iter().map(|id| records[id]).collect();
        Self {
            records,
            search_tree,
        }
    }

    fn fixup_ends(records: &mut [PerfSymbolLookupRecord], tree: &super::perf_tree::PerfSymbolTree) {
        let ordered = tree.indices_in_order();
        for pair in ordered.windows(2) {
            let previous = pair[0];
            let next_start = records[pair[1]].start;
            if records[previous].start == records[previous].end {
                records[previous].end = next_start;
            }
        }
        if let Some(&last) = ordered.last() {
            let record = &mut records[last];
            if record.start == record.end {
                record.end = round_up_to_page(record.start).saturating_add(4096);
            }
        }
    }

    fn remove_duplicates(
        records: &mut [PerfSymbolLookupRecord],
        candidates: &[super::PerfSymbolCandidate],
        tree: &mut super::perf_tree::PerfSymbolTree,
    ) {
        let ordered = tree.indices_in_order();
        let mut group_start = 0;
        while group_start < ordered.len() {
            let mut winner = ordered[group_start];
            let mut next = group_start + 1;
            while next < ordered.len() && records[ordered[next]].start == records[winner].start {
                let candidate = ordered[next];
                let current_size = records[winner].end.saturating_sub(records[winner].start);
                let candidate_size = records[candidate]
                    .end
                    .saturating_sub(records[candidate].start);
                if compare_duplicate_symbols(
                    &candidates[records[winner].candidate],
                    current_size,
                    &candidates[records[candidate].candidate],
                    candidate_size,
                ) == Ordering::Less
                {
                    assert!(tree.remove(winner));
                    winner = candidate;
                } else {
                    assert!(tree.remove(candidate));
                }
                next += 1;
            }
            group_start = next;
        }
    }

    pub(super) fn record_at(&self, offset: u64) -> Option<&PerfSymbolLookupRecord> {
        if let Some(tree) = &self.search_tree {
            return tree
                .lookup(offset, |index| {
                    let record = self.records[index];
                    (record.start, record.end)
                })
                .map(|index| &self.records[index]);
        }
        let index = self
            .records
            .partition_point(|record| record.start <= offset);
        let record = self.records.get(index.checked_sub(1)?)?;
        ((record.start == record.end && offset == record.start)
            || (record.start <= offset && offset < record.end))
            .then_some(record)
    }
}

fn compare_duplicate_symbols(
    current: &super::PerfSymbolCandidate,
    current_size: u64,
    candidate: &super::PerfSymbolCandidate,
    candidate_size: u64,
) -> Ordering {
    if (current_size == 0) != (candidate_size == 0) {
        return if current_size == 0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if let (Some(current_type), Some(candidate_type)) = (current.elf_type, candidate.elf_type)
        && current_type != candidate_type
    {
        if current_type == object::elf::STT_NOTYPE {
            return Ordering::Less;
        }
        if candidate_type == object::elf::STT_NOTYPE {
            return Ordering::Greater;
        }
    }
    if current.binding != candidate.binding {
        return if current.binding == super::PerfSymbolBinding::Weak {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if current.scope != candidate.scope {
        return if current.scope == super::PerfSymbolScope::Global {
            Ordering::Greater
        } else {
            Ordering::Less
        };
    }
    let current_underscores = leading_underscore_count(&current.name);
    let candidate_underscores = leading_underscore_count(&candidate.name);
    if current_underscores != candidate_underscores {
        return candidate_underscores.cmp(&current_underscores);
    }
    if current.name.len() != candidate.name.len() {
        return current.name.len().cmp(&candidate.name.len());
    }
    if current.name.starts_with("SyS") || current.name.starts_with("compat_SyS") {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

fn leading_underscore_count(name: &str) -> usize {
    name.bytes().take_while(|byte| *byte == b'_').count()
}

fn round_up_to_page(address: u64) -> u64 {
    address.saturating_add(4095) & !4095
}

struct PerfObjectSearchTree {
    root: usize,
    left: Vec<Option<usize>>,
    right: Vec<Option<usize>>,
}

impl PerfObjectSearchTree {
    fn from_tree(
        tree: &super::perf_tree::PerfSymbolTree,
        sorted_ids: &[usize],
        record_count: usize,
    ) -> Self {
        let mut sorted_by_id = vec![usize::MAX; record_count];
        for (sorted, &id) in sorted_ids.iter().enumerate() {
            sorted_by_id[id] = sorted;
        }
        let mut left = vec![None; sorted_ids.len()];
        let mut right = vec![None; sorted_ids.len()];
        for (sorted, &id) in sorted_ids.iter().enumerate() {
            let (tree_left, tree_right) = tree
                .children(id)
                .expect("active record is present in the construction tree");
            left[sorted] = tree_left.map(|child| sorted_by_id[child]);
            right[sorted] = tree_right.map(|child| sorted_by_id[child]);
        }
        Self {
            root: sorted_by_id[tree.root_index().expect("nonempty search tree")],
            left,
            right,
        }
    }

    fn lookup(&self, offset: u64, mut bounds_at: impl FnMut(usize) -> (u64, u64)) -> Option<usize> {
        let mut cursor = Some(self.root);
        while let Some(index) = cursor {
            let (start, end) = bounds_at(index);
            if offset < start {
                cursor = self.left[index];
            } else if end == start && offset == start {
                return Some(index);
            } else if offset >= end {
                cursor = self.right[index];
            } else {
                return Some(index);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PerfSymbolBinding, PerfSymbolCandidate, PerfSymbolScope};
    use super::*;

    fn candidate(
        name: &str,
        size: u64,
        scope: PerfSymbolScope,
        binding: PerfSymbolBinding,
    ) -> PerfSymbolCandidate {
        PerfSymbolCandidate {
            name: name.to_string(),
            address: 0x1000,
            size,
            bfd_size: size,
            elf_type: Some(object::elf::STT_FUNC),
            scope,
            binding,
            bfd_function_like: true,
            bfd_function: true,
        }
    }

    fn record(candidate: usize, start: u64, end: u64) -> PerfSymbolLookupRecord {
        PerfSymbolLookupRecord {
            candidate,
            start,
            end,
        }
    }

    #[test]
    fn table_fixup_precedes_duplicate_choice_and_uses_adjusted_lengths() {
        let candidates = [
            candidate(
                "weak_alias",
                0x100,
                PerfSymbolScope::Local,
                PerfSymbolBinding::Weak,
            ),
            candidate(
                "strong",
                0,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                "next",
                1,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
        ];
        let index = PerfSymbolLookupIndex::from_elf_tables(
            vec![
                record(0, 0x1000, 0x1010),
                record(1, 0x1000, 0x1000),
                record(2, 0x1010, 0x1011),
            ],
            std::slice::from_ref(&(0..3)),
            3..3,
            &candidates,
            true,
        );
        assert_eq!(index.record_at(0x1000).unwrap().candidate, 1);
    }

    #[test]
    fn a_table_tail_is_page_fixed_before_the_next_table_is_inserted() {
        let candidates = [
            candidate(
                "main_tail",
                0,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                "extra_tail",
                0,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
        ];
        let index = PerfSymbolLookupIndex::from_elf_tables(
            vec![record(0, 0x3ff8, 0x3ff8), record(1, 0x4000, 0x4000)],
            &[0..1, 1..2],
            2..2,
            &candidates,
            true,
        );
        assert_eq!(index.records[0].end, 0x5000);
        assert_eq!(index.records[1].end, 0x5000);
    }

    #[test]
    fn lookup_returns_linux_tree_first_hit_for_overlapping_records() {
        let candidates = [
            candidate(
                "wide",
                0x100,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                "middle",
                0x20,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                "inner",
                0x10,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
        ];
        let index = PerfSymbolLookupIndex::from_elf_tables(
            vec![
                record(0, 0x1000, 0x1100),
                record(1, 0x1080, 0x10a0),
                record(2, 0x1090, 0x10a0),
            ],
            std::slice::from_ref(&(0..3)),
            3..3,
            &candidates,
            false,
        );
        assert_eq!(index.record_at(0x1095).unwrap().candidate, 1);
        assert_eq!(index.record_at(0x109f).unwrap().candidate, 1);
        assert_eq!(index.record_at(0x10a0), None);
        assert_eq!(index.record_at(0x10ff), None);
        assert_eq!(index.record_at(0x1100), None);
    }

    #[test]
    fn nonoverlapping_records_include_last_byte_and_exclude_exact_end() {
        let candidates = [
            candidate(
                "first",
                0x10,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                "second",
                0x10,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
        ];
        let index = PerfSymbolLookupIndex::from_elf_tables(
            vec![record(0, 0x1000, 0x1010), record(1, 0x1010, 0x1020)],
            std::slice::from_ref(&(0..2)),
            2..2,
            &candidates,
            false,
        );
        assert_eq!(index.record_at(0x100f).unwrap().candidate, 0);
        assert_eq!(index.record_at(0x1010).unwrap().candidate, 1);
        assert_eq!(index.record_at(0x101f).unwrap().candidate, 1);
        assert_eq!(index.record_at(0x1020), None);
    }

    #[test]
    fn three_uncleaned_zero_length_aliases_use_native_rb_first_hit_not_last_sorted() {
        let candidates = [
            candidate(
                "first",
                0,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                "middle",
                0,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                "last",
                0,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
        ];
        let index = PerfSymbolLookupIndex::from_elf_tables(
            vec![
                record(0, 0x2000, 0x2000),
                record(1, 0x2000, 0x2000),
                record(2, 0x2000, 0x2000),
            ],
            &[],
            0..3,
            &candidates,
            false,
        );
        assert_eq!(index.record_at(0x2000).unwrap().candidate, 1);
    }

    #[test]
    fn extra_table_aliases_are_not_fixed_or_deduplicated() {
        let candidates = [
            candidate(
                "base",
                4,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate("extra", 0, PerfSymbolScope::Local, PerfSymbolBinding::Weak),
        ];
        let index = PerfSymbolLookupIndex::from_elf_tables(
            vec![record(0, 0x3000, 0x3004), record(1, 0x3000, 0x3000)],
            &[0..1, 1..2],
            2..2,
            &candidates,
            false,
        );
        assert_eq!(index.records.len(), 2);
        assert_eq!(index.records[1].candidate, 1);
        assert_eq!(index.records[1].end, 0x3000);
        assert_eq!(index.record_at(0x3000).unwrap().candidate, 0);
    }

    #[test]
    fn temporary_plt_header_is_removed_before_headerless_entries_are_inserted() {
        let candidates = [
            candidate(
                "tail",
                0x1000,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                ".plt",
                1,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
            candidate(
                "foo@plt",
                0x10,
                PerfSymbolScope::Global,
                PerfSymbolBinding::Global,
            ),
        ];
        let index = PerfSymbolLookupIndex::from_elf_tables_with_plt_header(
            vec![
                record(0, 0x1000, 0x2000),
                record(1, 0x1100, 0x1101),
                record(2, 0x1100, 0x1110),
            ],
            std::slice::from_ref(&(0..1)),
            1..3,
            &candidates,
            false,
            Some(PerfPltHeaderPhase {
                candidate: 1,
                remove_before_entries: true,
            }),
        );

        assert!(index.records.iter().all(|record| record.candidate != 1));
        assert_eq!(index.record_at(0x10ff).unwrap().candidate, 0);
        assert_eq!(index.record_at(0x1100).unwrap().candidate, 2);
        assert_eq!(index.record_at(0x110f).unwrap().candidate, 2);
        assert_eq!(index.record_at(0x1110), None);
    }

    #[test]
    fn permanent_plt_symbol_is_not_treated_as_a_temporary_header() {
        let candidates = [candidate(
            ".plt",
            0x10,
            PerfSymbolScope::Global,
            PerfSymbolBinding::Global,
        )];
        let index = PerfSymbolLookupIndex::from_elf_tables(
            vec![record(0, 0x1100, 0x1110)],
            std::slice::from_ref(&(0..1)),
            1..1,
            &candidates,
            false,
        );

        assert_eq!(index.record_at(0x110f).unwrap().candidate, 0);
        assert_eq!(index.record_at(0x1110), None);
    }
}
