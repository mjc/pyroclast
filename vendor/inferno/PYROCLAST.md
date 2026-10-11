# Wrapping-count fork

Based on the crates.io `inferno` 0.12.7 release, upstream commit
`967ed53e5d24587128781e3306e98f542303d57b`:
<https://github.com/jonhoo/inferno/tree/967ed53e5d24587128781e3306e98f542303d57b>.
The published crate SHA-256 is
`d2c05b9ae050366b3363927f59d2c07f922a746e97e2e96f70d479a3c7dbbbe5`.
The archive was extracted from the local Cargo registry cache. The original
CDDL-1.0 license and all other published files are included unchanged.

Only `src/collapse/common.rs` changes upstream code. `Occurrences::insert_or_add`
uses `u64::wrapping_add` for both the single-threaded and multi-threaded maps,
matching the published Inferno 0.12.8 release's unsigned addition behavior.
Overflow wraps modulo 2^64; representable counts, distinct-stack accounting,
parser state, and continuous-stream handling are unchanged. Multi-threaded
updates retain the existing DashMap entry lock. Explicit `wrapping_add` also
keeps this behavior consistent when workspace debug overflow checks are enabled.

Unit regressions in that file cover `MAX + 1`, repeated overflow, independent
stacks, exact-limit and ordinary representable sums, clearing output, and shared
concurrent updates. The published manifest, dependencies, features, upstream
tests, and existing lint attributes are unchanged. Upstream fixture-dependent
tests still require the unpublished fixtures and FlameGraph submodule.
