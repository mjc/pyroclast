# Retained-opener fork

Based on the crates.io `addr2line` 0.26.1 release, upstream commit
`ea55016a653014a0be6fc9f085ead564ede47fff`:
<https://github.com/gimli-rs/addr2line/tree/ea55016a653014a0be6fc9f085ead564ede47fff>.
The published crate SHA-256 is
`59317f77929f0e679d39364702289274de2f0f0b22cbf50b2b8cff2169a0b27a`.
The original MIT and Apache-2.0 licenses are included unchanged.

Only `src/loader.rs` changes upstream code. `Loader::new_with_opener` and
`Loader::new_with_sup_and_opener` retain a callback returning `Arc<[u8]>`.
All six input routes use it: main executable, supplementary file, dSYM
candidates, derived DWP, lazy DWO, and lazy Mach-O object/archive. The arena
retains the returned allocation without copying. The existing constructors
continue to open and mmap files, including lazy inputs.

Directory enumeration, optional-file error handling, dSYM UUID matching,
DWP-before-DWO lookup, DWO ID matching, archive member selection, decompression,
and relocation handling are unchanged. Snapshot policy belongs to the caller.
The published normalized manifest is used, with unused upstream dev-dependencies
removed; unpublished upstream test fixtures are not required. Fork coverage is
in the parent project's tests, not in an additional upstream test dependency tree.
