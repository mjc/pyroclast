# Perf-script parity: findings, bugs, and performance issues

Status as of 2026-06-11. Goal: `pyroclast plumbing fold|flamegraph` fully replaces
`perf script | inferno-collapse-perf | inferno-flamegraph`.

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
modern perf expands inline frames by default for DWARF-symbolized stacks — so the
dwarf comparison runs pyroclast with `--inline`. The remaining dwarf divergence is
the aarch64 unwind support (in progress; spec in `.ace-aarch64-unwind-spec.md`).

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
4. **Inline expansion on by default.** With debuginfo present pyroclast expands one
   address into multiple DWARF inline frames (DIE names like
   `catch_unwind<std::rt::lang_start_internal::{closure_env#0}, isize>`); plain
   `perf script` (the stated replacement target — no `--inline`) prints exactly one
   symtab-named line per callchain entry. The expansion mirrors `perf script --inline`
   and should be opt-in.
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

## The two open .beads parity issues reduce to one model (x86_64 dwarf path)

From `.ace-research-perf-unwind.md`: libdwfl always fires the frame callback once for
the sampled IP before unwinding, and perf keeps partial stacks. So:

- **pyroclast-5gr** (current-IP-only stacks): pyroclast must emit the single leaf
  (plus inlines when enabled) when the initial IP reported into a module and neither
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
  `CachedObjectMetadata` caches symbols but not parsed DWARF. Making inline expansion
  opt-in removes this from the default path; the cache is still worth adding for
  `--inline`.
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
