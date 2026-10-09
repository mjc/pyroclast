# Private GNU Input Provider

`nix/binutils-provider.nix` packages `pyroclast-addr2line` separately from GNU
`addr2line`. It does not override `pkgs.binutils`, shadow the independent
oracle, or change Pyroclast's in-process Rust default.

Default symbolization remains in-process `rust-addr2line`. This helper is an
optional GNU backend component, not a replacement default or an automatic
fallback. On Linux, external GNU symbol-only batches pass the selected primary
bytes through a sealed inherited descriptor. The helper is a Linux/Darwin development
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

Darwin additionally enables x86-64 and aarch64 ELF targets for Linux recordings.
`bfd/config.bfd` otherwise selects only Mach-O for Darwin, while
`bfd/configure.ac` accepts additional configurations through `--enable-targets`.
The same recorded flag is applied to the separately built, unpatched oracle;
native platform flags and the source patch set remain unchanged.

`licenses/` contains verbatim upstream COPYING files and extracted component
copyright/license notices from the exact archive. These notices describe the
GNU components, not a license choice for Pyroclast or its newly authored files.
The project's license-policy decision remains separate.

## Bootstrap Contract

Linux uses memfd/procfs; Darwin uses unlinked, read-only temporary backing.
Before invoking the helper, the caller supplies:

- `PYRO_PRIMARY_FD`: inherited descriptor holding the already-selected primary
  bytes, not a request to reopen the pathname. The helper consumes this FD.
- `PYRO_PRIMARY_NAME`: original logical filename, exactly matching `-e`.
- `PYRO_PRIMARY_CANONICAL`: original canonical filename captured at selection.

Missing or invalid bootstrap data fails closed. Normal GNU help/version exits
remain available without a primary. The existing GNU stdin address protocol
is unchanged. Rust retains selected primary bytes and canonical names in its
object cache and lazily starts one owned, cancellable helper per selected DSO
for external symbol-only requests.
It constructs the sealed transport once, lazily on the first external batch,
from those bytes, not by reopening the path. The selected DSO owns that
transport until its resolver is dropped; subsequent batches borrow the same
sealed file. Base-only and in-process lookups do not create the transport.
The child receives a dedicated descriptor without changing the parent's
close-on-exec flags. The helper retains its primary and auxiliary snapshots
between batches and is killed/reaped when its selected DSO is dropped.

GNU `-f` without `-i` emits a function/file line pair and flushes after each
stdin address (`binutils/addr2line.c:287-430`). The real Unix runner keeps stdin
open and exchanges one such framed response per address. A five-second deadline
covers each response, not an entire batch or the helper's idle lifetime. The
duration follows perf's default in `tools/perf/util/symbol.c:72`; perf's command
backend applies it to read waits in `util/addr2line.c:335`, whereas Pyroclast
uses a total request/response budget. Neither is a real-time filesystem bound.
Malformed replies, EOF, cancellation or timeout close/reap the owned session
and report an error; no partial response, live reopen, or automatic restart is
substituted. Legacy custom `CommandRunner` implementations can explicitly
decline sessions and retain their existing whole-command execution contract.

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
read-only descriptors, Linux seals, cache close/reopen metadata and filename,
supplied-FD routing, rejected streams/writes without unlinking, FIFO negative
caching, stable canonical aliases after symlink retargeting, and auxiliary
survival after rewrite and deletion. Installed-helper checks rerun the native
suite after relocation/fixup without build-library environment overrides.

The API proof runs again with `PYRO_PORTABLE_SNAPSHOTS` defined at compile time.
That test poisons `memfd_create`, so it cannot accidentally pass by using the
Linux adapter. The portable adapter creates backing in a private directory,
opens an independent read-only descriptor, verifies its device/inode, and
unlinks the file and directory before copying. Only that descriptor survives
the completed copy; no writable descriptor is published. It observes the same
finite input extent and preserves the input descriptor's offset.

Without procfs, each BFD consumer receives an independent unlinked read-only
copy of the retained snapshot, never of the live logical pathname. This
preserves independent offsets without relying on `/dev/fd` behaving like a
new open-file description. It does add copy/storage work per consumer and is
not a performance optimization. Invalid temporary storage fails without a
Linux or live-input fallback. This compile-time adapter is not a user option.
The helper package is available on Linux and Darwin. Its build and installed
checks compare full native stdout after live primary replacement and reject
missing bootstrap data. Darwin also runs those checks for x86-64 and aarch64
ELF objects, independently of its native Mach-O control. The Rust handoff is
still Linux-only; package proofs do not establish Darwin Rust integration.

## Bounds And Integration

Copying observes a finite extent and rejects short reads; it does not chase a
growing file's EOF. Concurrent writes can affect acquisition: this is not an
atomic filesystem snapshot, but the completed copy is immutable and shared by
all CRC/parse/reopen consumers. `O_NONBLOCK` does not bound regular-file I/O on
a stalled filesystem, and a very large finite file can consume time/storage.
The Rust runner retains owned process-group cancellation and applies response
deadlines once the helper is spawned. Parent-side regular-file acquisition,
tool probing/spawn, and uninterruptible kernel I/O are not bounded by that
response timer; kill/reap cannot promise a hard real-time bound for kernel I/O.
Trusted plugin code loading is not sandboxed; this is not a general BFD sandbox.

Remaining integration: immutable backing where Linux memfd/procfs is unavailable
and isolation for stalled parent-side filesystem acquisition.
Non-Linux external GNU still has the legacy pathname handoff, without this
provider's snapshot guarantee. The default in-process Rust path does not use
that external handoff.
