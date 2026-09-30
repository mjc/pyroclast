# Perf-script parity: findings, bugs, and performance issues

Status as of 2026-06-11. Goal: `pyroclast plumbing fold|flamegraph` fully replaces
`perf script | inferno-collapse-perf | inferno-flamegraph`.

## 2026-09-30 streaming replay and folded storage

Replay delivers samples against the maps visible at their ordered delivery,
then discards their decoded payloads. Ordering retains timestamp/file-offset
pairs, not decoded samples or a recording-wide raw-stack trie. File input uses
separate reusable scan and delivery windows so backlog replay cannot repeatedly
evict the sequential window. The CLI writes perf text directly to its writer.

Folded stacks retain integer IDs for normalized serialized label segments.
Names are interned once; normalization caches store ID sequences rather than
full rendered labels. Existing stack lookup borrows the current ID slice, and
only a new unique stack allocates its stored sequence. Serialization happens
once per final stack. Sorting compares serialized bytes including delimiters,
as Inferno's `src/collapse/common.rs` sorts its final string keys.

Symbol caches retain borrowed raw frame lists and perf metadata, not a second
folded rendering. Folding skips already-cached addresses before constructing
prefetch batches. Base-only and inline-capable lookup remain distinct: perf's
event-line IP goes through `machine__resolve`, whereas callchains can expand
inlines. This changes storage and delivery, not libdw's PC adjustment or
binutils addr2line's `bfd_find_inliner_info` expansion.

A previously green test confused an empty normalized label with a missing
symbol: it invented a module fallback for a resolved `(python)` frame. Inferno's
`src/collapse/perf.rs:on_stack_line` returns immediately for names beginning
with `(`; `after_event` emits only nonempty stacks. The corrected test fails on
the prior implementation and requires no output for a process-name-only stack.
Unresolved symbols still use Inferno's module fallback.

Mapping lookups now reuse a containing cached index after validating the
current entry's PID, address range, and CPU-mode predicate. This relies on
the same per-PID disjoint-range invariant as perf's
`tools/perf/util/maps.c:__maps__fixup_overlap_and_insert`, not on retaining a
stale mapping across mutations. The old "cached" lookup never read its cache;
a red test observed 256 index searches for 256 addresses in one mapping.
Regression tests compare cached and uncached lookups after splits, complete
remaps, index shifts, PID switches, and CPU-mode changes.

Ten paired Hyperfine runs on the replay recording, reversing command order
each pair, measured median wall time 11.908s before versus 9.836s after
(17.4% lower), with mean user CPU 7.216s versus 5.744s. The machine was loaded;
these are paired measurements, not an unloaded absolute runtime claim.
Both direct folding and streamed perf text through Inferno matched a freshly
executed native perf/Inferno reference byte-for-byte.

## 2026-09-29 x86-64 replay

Fresh output from the 390,376,668-byte `inferno-slow-collapse.perf.data` was
compared with perf 7.2.5 and Inferno 0.12.8. The committed code initially
produced the same 1,505 folded stacks and total period, but used `__clone3`
where perf used `__GI___clone3`, and `memcpy` where perf used
`memcpy@@GLIBC_2.14`. Perf's symbol chooser kept the preferred ELF aliases;
Pyroclast had promoted binutils-style function records even when BFD had no
`STT_FILE` filename for them. Commit `308faf6` records filename eligibility
from the ELF symbol table before using that fallback.

After the fix, `perf script --force -i <perf.data> | inferno-collapse-perf -q`
and `pyroclast plumbing fold --count-periods <perf.data>` are byte-identical:
1,505 lines, 609,079 bytes, SHA-256
`124a24929267f42da993195bdf1aa12a37bb30d67d83ee455bf2a9e0cf8e4f47`.
The recording's `entropy_burn` executable is unavailable on this machine, so
its frames resolve to the module fallback in both pipelines. This result does
not establish parity for that executable when its symbols are present.

Companion deep-dives produced during this investigation:

- `.ace-research-perf-unwind.md` — source-cited model of perf + elfutils libdw user
  unwinding (the decision table for 0 / 1 / N frames per sample, and the gate for
  skipping unwinds perf would never attempt).
- `.ace-review-findings.md` — full code review (12 performance, 7 correctness findings).

## Oracle harness

`scripts/perf-oracle` (new) builds a Docker image (Ubuntu + modern perf + inferno),
records `dwarf` and `fp` call-graph profiles of `scripts/oracle/workload.rs`, exports
real `perf script` text and `inferno-collapse-perf` folds, then runs pyroclast against
the same `perf.data` inside the container. Artifacts land in `target/oracle/`. perf
cannot run on macOS, so this is the only local ground truth; previous parity numbers in
`.beads/issues.jsonl` came from an x86_64 Linux machine that is not this one.

Important variance pinned down: **symbol naming depends on the perf build**. Debian
trixie's perf 6.12 does not demangle Rust v0 (`_RNv...` stays raw) while modern perf
(>= 6.16) and pyroclast demangle it. The oracle image deliberately uses a modern perf.
Byte parity is only meaningful against a pinned perf version; record
`target/oracle/perf.version` with any saved numbers.

## Status update (later on 2026-06-11)

The six gaps below are FIXED and merged: `pyroclast plumbing perf-script` output is
now byte-identical to `perf script --force` on the fp oracle, and the folded output
differs only where `inferno-collapse-perf` itself mis-parses the space-containing
DSO path `/ (deleted)` (it keeps the `+0x9c` offset and a trailing space on
`__libc_start_main` and emits `[unknown] `); pyroclast's folding of those frames is
deliberately the more correct one. Two genuine parser bugs fell out of this work:
the perf feature bitmap was read at byte offset 56 instead of 72 (silently
disabling HEADER_EVENT_DESC and header build-ids — `struct perf_file_header`
places `adds_features` after the three file sections), and feature-section
build-id records (which carry `header.type == 0`) were rejected.

Dwarf note: the dwarf oracle's `perf script` output contains `(inlined)` frames —
modern perf expands inline frames by default for DWARF-symbolized stacks. Pyroclast's
parity paths therefore keep the inline-capable renderer on for every profile: fp data
with no printable inline DIEs still renders one frame per callchain entry, while DWARF
data can match perf's `(inlined)` rows. Pyroclast keeps `--inline` available as an
explicit no-op for parity with perf, and provides `--no-inline` as the opt-out.

## Parity gaps found via the oracle (fp call-graph path, arch-independent)

Measured by diffing `target/oracle/fp.pyroclast.script` against `fp.perf.script`
(same `perf.data`, recorded with `--call-graph fp`):

1. **Event name suffix missing.** perf prints `task-clock:ppp:`; pyroclast prints
   `task-clock:`. perf script takes event names from the HEADER_EVENT_DESC feature;
   pyroclast reconstructs from the attr and loses the precision modifiers.
2. **Symbolized frames print `([unknown])` instead of the DSO path.** Multi-label and
   callchain frames go through a writer that hardcodes the unknown DSO; perf prints
   the mapping's long path for every mapped frame.
3. **Double symbol offset.** Lines like `quicksort+0x854+0x0` — a label that already
   carries `+0xNNN` gets a second offset appended in the symbolized script path.
4. **Historical correction: inline expansion was treated as a bug.** The fp oracle
   rendered one symtab-named line per callchain entry, and the initial fix wrongly
   generalized that into "plain `perf script` never emits inline frames." The arm64
   DWARF oracle and the x86-64 `inferno-slow-collapse.perf.data` run both disprove
   that: real `perf script` emits `(inlined)` rows when the stack and debuginfo make
   them printable. The parity path should be inline-capable by default; fp data remains
   single-frame naturally.
5. **Dropped callchain entry.** A real frame (`...+0x6cb`, adjacent-but-distinct ip to
   its neighbor) disappears from pyroclast's output; perf does not dedupe entries.
6. **Basename instead of full DSO path** for unsymbolized mapped frames
   (`[unknown] (libc.so.6)` vs `[unknown] (/usr/lib/aarch64-linux-gnu/libc.so.6)`).

These six are being fixed against the oracle byte-diff (in progress). The base symtab
naming itself (candidate selection, interval lookup, offset formatting) already matches
perf — prior commits got that right.

## Architecture gap: aarch64 DWARF unwind — RESOLVED

aarch64 DWARF user unwinding is now wired through the fold path (PerfUserRegs
per-arch decoding via HEADER_ARCH, per-arch framehop unwinders, arch-gated no-CFI
fallbacks; the aarch64 fallback fires when framehop yields only the seed pc, since
elfutils' aarch64 ebl_unwind recovers a caller from lr with no fp>=sp
precondition). The dwarf oracle's call spine now matches perf frame-for-frame by
address. Remaining dwarf divergence is inline-NAME parity, not unwinding:

- perf expands more leaf inline frames at some IPs than pyroclast, and marks them
  `(inlined)`;
- inline name spelling: pyroclast emits DWARF DIE names (`sort<u64, fn(&u64,
  &u64) -> bool>`), perf's srcline backend emits qualified names
  (`core::slice::sort::unstable::sort`);
- perf prints trailing `[unknown]` frames for PAC-tagged return addresses that
  framehop strips.

### Inline-name parity — RESOLVED (later 2026-06-11)

All four inline gaps closed: names come from DW_AT_linkage_name demangled the way
perf itself demangles (its external addr2line runs without -C), sampled-IP leaves
expand through the full inline chain (perf runs append_inlines on every accepted
entry — the earlier "over-expansion" read was actually under-expansion elsewhere),
inline script lines render `sym+0xoff (inlined)` sharing the base frame's offset,
and `[kernel.kallsyms]` frames resolve from live /proc/kallsyms when
/sys/kernel/notes matches the recorded kernel build-id. The dwarf oracle script and
folded outputs now match perf byte-for-byte EXCEPT perf's PAC-tagged `[unknown]`
frames (perf prints aarch64 lr values without stripping pointer-auth bits;
pyroclast/framehop strips them — intentional divergence, arguably a perf bug).
A `.debug_str`-based generic specialization was removed from the inline path: it
rewrote qualified names into spellings perf never prints.

### Historical note (pre-fix analysis)

perf's inline-frame names depend on which srcline backend its build uses: libbfd,
libllvm, libdw, or an external `addr2line` subprocess. The Ubuntu oracle perf uses
the external addr2line backend and prints fully-qualified, v0-demangled names
(`std::panicking::catch_unwind::<isize, std::rt::lang_start_internal::{closure#0}>`)
with `(inlined)` in the DSO column and symbol offsets on base frames. pyroclast's
DIE-walking resolver (built to match a libdw-backed perf in earlier commits
decabb1/bfb75c4) emits bare `DW_AT_name` spellings (`catch_unwind<isize, ...>`)
without qualification. Decision: align with the qualified-name behavior (it is the
modern, measurable oracle here and the more useful output) and treat the libdw
spelling as documented variance. Also observed: pyroclast expands inline frames at
one return address where perf does not (suspect a missing pc-1 adjustment on
non-leaf inline lookups), and kernel frames currently fold as `[[kernel.kallsyms]]`
because kallsyms symbolization isn't wired into the direct fold.

## Original note (pre-fix)

The user-stack unwind model is x86_64-only (`PerfX86_64Regs`, rbp/rsp heuristics,
x86_64 elfutils arch fallback). On arm64 perf.data with `--call-graph dwarf`, pyroclast
folds almost nothing (5 samples vs the full set; bench: 2 folded lines vs oracle 15).
Local development on Apple Silicon records arm64 in Docker, so this blocks oracle-driven
work on the dwarf path. Needs: per-arch reg-mask decoding (the regs are already read by
mask), framehop's aarch64 unwinder, and the aarch64 `ebl_unwind` (x29 chain) analogue.
Tracked as follow-up; the fp path works on any arch.

## The two .beads parity issues — CLOSED (leaf-only model landed)

pyroclast-5gr and pyroclast-pkh are closed. The leaf-only predicate is implemented
exactly as sourced: emit (or truncate to) the single seeded-IP leaf when the
initial IP reported into a module, no FDE covers it, and the arch ebl fallback
cannot advance (x86_64 `bp < sp` per backends/x86_64_unwind.c's `sp >= fp+16`
guard; aarch64 `lr == 0`). When CFI covers the ip the sample stays MustUnwind —
an FDE row with undefined RA (clean leaf) and one with a real caller are
indistinguishable without unwinding (libdwfl handle_cfi). The same classification
runs before framehop (SkipUnwind | LeafOnly | MustUnwind, memoized per (pid, ip)),
CFI presence is memoized per ip, and the module-report retry loop re-unwinds only
when a module actually loaded (PERF-4). The unsourced .so-vs-exe initial-frame
policy was removed. Validation caveat: the original 114-vs-144 folded-line gap was
measured against an x86_64 perf.data we cannot regenerate locally; the model is
test-pinned to the cited elfutils/perf sources and the arm64 oracle is unchanged,
but re-running the original x86_64 comparison on a Linux x86 box remains the final
confirmation.

## Original analysis (historical)

From `.ace-research-perf-unwind.md`: libdwfl always fires the frame callback once for
the sampled IP before unwinding, and perf keeps partial stacks. So:

- **pyroclast-5gr** (current-IP-only stacks): pyroclast must emit the single leaf
  (plus printable inlines) when the initial IP reported into a module and neither
  CFI (`has_unwind_info_for_ip`) nor the rbp fallback (`bp >= sp`) can produce a
  caller. The hook exists (`object_unwind_initial_frame_policy`) but is currently
  ignored in `perf_accepted_object_unwind_frames`.
- **pyroclast-pkh** (unwind dominates runtime): the same predicate, evaluated *before*
  unwinding, lets pyroclast skip framehop entirely for leaf-only samples. Recommended
  caches: per-evsel attr bits, per-(module, page) CFI presence, and a per-(pid, ip)
  `SkipUnwind | LeafOnly | MustUnwind` classification.

## Performance issues (from code review; see `.ace-review-findings.md` for all 12)

- **PERF-1 (critical, likely the rc=124 root cause):** `PerfDwarfNameResolver` fully
  re-parses each DSO's DWARF (object parse + DIE walk) on every fold round —
  `CachedObjectMetadata` caches symbols but not parsed DWARF. Since parity keeps the
  inline-capable path on, this cache is required for the default path rather than only
  for an opt-in mode.
- **PERF-2/3 (fixed):** mmap ingestion re-scanned and re-indexed the whole mapping
  table per record (two independent O(n²) patterns). Now incremental via the per-pid
  interval index; overlap splits keep the perf-faithful path.
- **PERF-4:** per-sample stacks can be re-unwound up to 9× by the module-report
  convergence loop (`MAX_LIBDW_CALLBACK_REPORT_PASSES`); skip the redundant final pass
  when no new module was reported.

## Correctness bugs

- **CORR-1:** `file_matches_recorded_identity` compares only inode, ignoring device
  major/minor — wrong-binary symbolization is possible across filesystems.
- **CORR-2:** the same file can get two `symbol_source_id`s depending on mmap record
  form, defeating symbol-cache dedup (amplifies PERF-1).
- **macOS `cargo pyroclast` was broken (fixed):** package discovery compared a
  canonicalized crate root against cargo's un-canonicalized manifest paths, failing
  through `/var -> /private/var`.
- **Silent FakeBackend fallback:** on macOS, `pyroclast memory|latency|offcpu` quietly
  run the fake backend and write fake artifacts instead of erroring out as unsupported.

## Test-suite portability (macOS/aarch64 host) — RESOLVED

22 of 621 tests originally failed on a fresh macOS machine (the suite was developed
on x86_64 Linux). All fixed: cargo metadata path canonicalization (7 `cargo_cli`),
explicit platform injection through the existing `_on_platform` entry points
(8 `run_cli` + the FakeBackend-exposing e2e test), a portable `read_dir` procfs walk
(2 `platform`, and the `procfs` dependency is gone), a canonicalized expectation in
the NixOS System.map test, and a synthetic x86_64 ELF fixture replacing
`std::env::current_exe()` in the 5 current-IP-only unwind tests (the host test
binary's Mach-O `__unwind_info` recovered callers a Linux ELF would not). The suite
is now fully green on macOS: 641/641, clippy clean.

Note for fixture authors: framehop applies a frame-pointer fallback for addresses
OUTSIDE any known module, but stops at uncovered addresses INSIDE a module that has
CFI — synthetic unwind fixtures must include an eh_frame (even one whose only FDE
covers an unrelated range) to pin the no-coverage behavior.

## Environment notes

- AGENTS.md says nix, but this machine has no nix; everything here runs with rustup
  cargo + Docker. The pre-commit hook (`.githooks`) is configured by the nix shellHook
  and is not active here; `nix flake check` in it cannot run without nix.
- `inferno` and `cargo-nextest` are installed via `cargo install` on this machine.
