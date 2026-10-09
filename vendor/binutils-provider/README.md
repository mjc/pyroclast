# Private GNU Input Provider

`nix/binutils-provider.nix` packages `pyroclast-addr2line` separately from GNU
`addr2line`. It does not override `pkgs.binutils`, shadow the independent
oracle, or change Pyroclast's in-process Rust default.

Default symbolization remains in-process `rust-addr2line`. This helper is an
optional GNU backend component, not a replacement default or an automatic
fallback. On Linux, external GNU symbol-only batches pass the selected primary
bytes through a sealed inherited descriptor. The helper is a Linux development
test dependency, not a dependency of the default application package.

## Provenance

The source is GNU binutils-with-gold **2.46**. `provenance.json` records the
upstream archive URL/SHA256, locked nixpkgs revision, ordered hashes of its
eight source patches, provider patch hash, and original prototype oracle.
The derivation rejects a different base version, archive hash, or patch set.
The local binutils-gdb 2.46.50 checkout was an audit reference, not build input.

The private build inherits the pinned GNU target/configuration flags. It adds
the provider patch and explicitly retains the independent base package's
configured global debug directory. BFD's logical filenames and its discovery
order, debuglink CRC checks, build-ID lookup, altlink behavior, DWARF parsing
and output formatting remain GNU's. Only addr2line and its private shared
libraries are installed; the sole executable is `pyroclast-addr2line`.

`licenses/` contains verbatim upstream COPYING files and extracted component
copyright/license notices from the exact archive. These notices describe the
GNU components, not a license choice for Pyroclast or its newly authored files.
The project's license-policy decision remains separate.

## Bootstrap Contract

Linux memfd/procfs is required. Before invoking the helper, the caller supplies:

- `PYRO_PRIMARY_FD`: inherited descriptor holding the already-selected primary
  bytes, not a request to reopen the pathname. The helper consumes this FD.
- `PYRO_PRIMARY_NAME`: original logical filename, exactly matching `-e`.
- `PYRO_PRIMARY_CANONICAL`: original canonical filename captured at selection.

Missing or invalid bootstrap data fails closed. Normal GNU help/version exits
remain available without a primary. The existing GNU stdin address protocol
is unchanged. Rust retains selected primary bytes and canonical names in its
object cache and starts an owned, cancellable helper for each symbol-only batch.
It constructs the sealed transport from those bytes, not by reopening the path.
The child receives a dedicated descriptor without changing the parent's
close-on-exec flags. Persistent per-DSO helper sessions are not implemented.

Auxiliary candidates are opened once, nonblocking and without terminal
acquisition; only regular files with finite observed lengths are copied.
Successful snapshots, failed candidates and logical aliases are cached for the
session. All consumer descriptors reference sealed, read-only bytes with
independent offsets. CRC probing, parsing and BFD cache reopens see the same
snapshot. Internal `/proc/self/fd` opens refer only to held sealed objects;
they are never substituted for the original `-e` or BFD filename. There is no
LD_PRELOAD, output filtering, live fallback or arbitrary file-size cap.

## Native Tests

On Linux x86_64, with the repo's devenv and a built helper:

```sh
bash vendor/binutils-provider/tests/check-native.sh /path/to/pyroclast-addr2line /path/to/independent/addr2line
bash vendor/binutils-provider/tests/check-native.sh --stock /path/to/independent/addr2line
```

The first command must exit 0. The second deliberately reproduces actual RED:
three valid controls pass and three race cases fail, returning exit 1.

- Valid primary, debuglink, and `DW_FORM_GNU_strp_alt` controls compare complete
  stdout with independently executed, unpatched GNU.
- Replacing the live primary after selecting its bytes must not change the
  result; the helper must make zero live opens of the primary pathname.
- Replacing a debuglink file after the native CRC probe closes must not cause
  different bytes to be parsed; the helper must open the auxiliary only once.
- Replacing an altlink candidate with a FIFO after the native existence probe
  closes must not block the later parse; the captured alternate leaf must remain.
- Invoking the private helper without selected bytes must fail without stdout,
  not silently reopen the live primary.

Shell builds fixtures in an owned temporary directory and removes them on
exit. Python is confined to ptrace barriers, immutable primary selection,
identity checks and native process supervision, not fixture creation. Each
tracee has a strict four-second deadline and separate one-second kill/reap
deadline; cleanup checks its start time and full command and never signals a
process group. Syscall/register details are explicitly Linux x86_64. Other
Linux architectures can build the adapter but do not claim this ptrace proof.

During the Nix build, `tests/api-proof.c` also verifies independent offsets,
seals, cache close/reopen metadata and filename, supplied-FD routing, rejected
streams/writes without unlinking, FIFO negative caching, and stable canonical
aliases after symlink retargeting. Installed-helper checks rerun the native
suite after relocation/fixup without build-library environment overrides.

## Bounds And Integration

Copying observes a finite extent and rejects short reads; it does not chase a
growing file's EOF. Concurrent writes can affect acquisition: this is not an
atomic filesystem snapshot, but the completed copy is immutable and shared by
all CRC/parse/reopen consumers. `O_NONBLOCK` does not bound regular-file I/O on
a stalled filesystem, and a very large finite file can consume time/storage.
The Rust runner retains owned process-group cancellation; automatic wall-clock
deadlines are not implemented yet.
Trusted plugin code loading is not sandboxed; this is not a general BFD sandbox.

Remaining integration: wall-clock deadlines, supervised persistent per-DSO
helper sessions, and immutable backing where Linux memfd/procfs is unavailable.
Non-Linux external GNU still has the legacy pathname handoff, without this
provider's snapshot guarantee. The default in-process Rust path does not use
that external handoff.
