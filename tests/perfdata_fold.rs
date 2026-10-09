// Only the linux-gated libc leaf test parses real objects.
#[cfg(target_os = "linux")]
use object::{Object as _, ObjectSegment as _, ObjectSymbol as _};
use proptest::prelude::*;
use pyroclast::perfdata::fold::{
    FoldOptions, fold_perfdata_callchains, fold_perfdata_callchains_with_options,
    fold_perfdata_callchains_with_symbols, fold_perfdata_file_with_options, summarize_perfdata,
};
use pyroclast::perfdata::mappings::FileIdentity;
use pyroclast::perfdata::records::{
    PERF_RECORD_FINISHED_ROUND, PERF_RECORD_FORK, PERF_RECORD_MISC_COMM_EXEC,
    PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_USER, PERF_RECORD_MISC_MMAP_BUILD_ID,
    PERF_RECORD_SAMPLE,
};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP,
    PERF_SAMPLE_PERIOD, PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME,
};
use pyroclast::symbols::{
    ResolvedSymbolFrames, SymbolRequest, SymbolResolver,
    perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources,
};
use std::cell::RefCell;
#[cfg(target_os = "linux")]
#[path = "support/kcore_inputs.rs"]
mod kcore_inputs;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "support/perfdata_memory_sources.rs"]
mod memory_sources;

#[cfg(target_os = "linux")]
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

fn render_unknown_folded_callchain(frames: &[u64], count: u64) -> String {
    if frames.is_empty() {
        return String::new();
    }

    let mut rendered = String::from(":12");
    for _ in frames.iter().rev() {
        rendered.push_str(";[unknown]");
    }
    rendered.push(' ');
    rendered.push_str(&count.to_string());
    rendered.push('\n');
    rendered
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
enum LiveCfiSource {
    WithCfi,
    WithoutCfi,
    Missing,
    Invalid,
    Unreadable,
    NonRegular,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct CfiSourceFixture {
    _root: tempfile::TempDir,
    home: std::path::PathBuf,
    data: std::path::PathBuf,
    expected_ips: Vec<u64>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn compile_cfi_source_elf(source: &std::path::Path, binary: &std::path::Path, cached: bool) {
    let mut compiler = Command::new("cc");
    compiler.args([
        "-nostdlib",
        "-no-pie",
        "-Wl,-e,identity_leaf",
        "-Wl,-Ttext=0x401000",
        "-Wl,--eh-frame-hdr",
    ]);
    if cached {
        compiler.args(["-DCACHE_CFI", "-Wl,--build-id=0xaabbccdd"]);
    } else {
        compiler.arg("-Wl,--build-id=0x11223344");
    }
    let output = compiler
        .arg(source)
        .arg("-o")
        .arg(binary)
        .output()
        .expect("compile CFI source fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn replace_live_cfi_source(live_source: LiveCfiSource, live: &std::path::Path) {
    match live_source {
        LiveCfiSource::WithCfi | LiveCfiSource::WithoutCfi => {}
        LiveCfiSource::Missing => {
            std::fs::remove_file(live).expect("remove live ELF");
        }
        LiveCfiSource::Invalid => {
            std::fs::write(live, b"not an ELF").expect("invalidate live ELF");
        }
        LiveCfiSource::Unreadable => {
            std::fs::remove_file(live).expect("remove live ELF");
            // ELOOP makes the live path unreadable even when tests run as root.
            std::os::unix::fs::symlink(live, live).expect("unreadable live path");
            assert!(std::fs::read(live).is_err());
        }
        LiveCfiSource::NonRegular => {
            std::fs::remove_file(live).expect("remove live ELF");
            std::fs::create_dir(live).expect("non-regular live path");
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cfi_source_fixture(live_source: LiveCfiSource) -> CfiSourceFixture {
    let root = tempfile::tempdir().expect("CFI source fixture");
    let home = root.path().join("home");
    let live = root.path().join("live.elf");
    let cached = pyroclast::symbols::perf_build_id_elf_path(&home.join(".debug"), "aabbccdd");
    std::fs::create_dir_all(cached.parent().expect("cache parent")).expect("cache directory");
    let source = root.path().join("identity.S");
    std::fs::write(&source, ".text\n.globl identity_leaf\n.type identity_leaf,@function\nidentity_leaf:\n.cfi_startproc\n#ifdef CACHE_CFI\n.cfi_def_cfa %rsp,16\n#else\n.cfi_def_cfa %rsp,8\n#endif\n.cfi_offset %rip,-8\n.fill 16,1,0x90\nret\n.cfi_endproc\n.size identity_leaf,.-identity_leaf\n.p2align 5\n.globl caller_live\n.type caller_live,@function\ncaller_live:\n.cfi_startproc\n.cfi_def_cfa %rsp,8\n.cfi_undefined %rip\n.fill 16,1,0x90\nret\n.cfi_endproc\n.size caller_live,.-caller_live\n.p2align 5\n.globl caller_cache\n.type caller_cache,@function\ncaller_cache:\n.cfi_startproc\n.cfi_def_cfa %rsp,8\n.cfi_undefined %rip\n.fill 16,1,0x90\nret\n.cfi_endproc\n.size caller_cache,.-caller_cache\n.section .note.GNU-stack,\"\",@progbits\n").expect("CFI assembly");
    compile_cfi_source_elf(&source, &live, false);
    compile_cfi_source_elf(&source, &cached, true);
    if matches!(live_source, LiveCfiSource::WithoutCfi) {
        let output = Command::new("objcopy")
            .args([
                "--remove-section=.eh_frame",
                "--remove-section=.eh_frame_hdr",
            ])
            .arg(&live)
            .output()
            .expect("strip live CFI");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let bytes = std::fs::read(&live).expect("live ELF");
    let elf = object::File::parse(bytes.as_slice()).expect("parse live ELF");
    assert_eq!(elf.kind(), object::ObjectKind::Executable);
    assert_ne!(
        elf.build_id().expect("live ID"),
        Some(&[0xaa, 0xbb, 0xcc, 0xdd][..])
    );
    let symbol = |name| {
        elf.symbols()
            .find(|s| s.name() == Ok(name))
            .expect("fixture symbol")
            .address()
    };
    let ip = symbol("identity_leaf") + 1;
    let caller_live = symbol("caller_live");
    let caller_cache = symbol("caller_cache");
    let mut stack = [0; 64];
    stack[..8].copy_from_slice(&(caller_live + 1).to_le_bytes());
    stack[8..16].copy_from_slice(&(caller_cache + 1).to_le_bytes());
    let data = root.path().join("perf.data");
    let recording = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes_with_misc(
                10,
                PERF_RECORD_MISC_CPUMODE_USER | PERF_RECORD_MISC_MMAP_BUILD_ID,
                &mmap2_build_id_payload(
                    11,
                    12,
                    0x0040_0000,
                    0x0001_0000,
                    0,
                    live.to_str().expect("live path"),
                ),
            ),
            record_bytes_with_misc(
                9,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample_payload_with_user_stack(
                    ip,
                    11,
                    12,
                    [0xffff_ffff_ffff_fe00, ip],
                    2,
                    [0, 0x7000_0000, ip],
                    stack,
                ),
            ),
        ],
    );
    std::fs::write(&data, recording).expect("write recording");
    // perf util/unwind-libdw.c:108-123 selects a reported live module even if
    // its ID is wrong or it has no CFI (libdwfl/dwfl_report_elf.c:302-325).
    replace_live_cfi_source(live_source, &live);
    let mut expected_ips = vec![ip, ip];
    match live_source {
        LiveCfiSource::WithCfi => expected_ips.push(caller_live),
        LiveCfiSource::WithoutCfi => {}
        _ => expected_ips.push(caller_cache),
    }
    CfiSourceFixture {
        _root: root,
        home,
        data,
        expected_ips,
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct CfiAddressResolver;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SymbolResolver for CfiAddressResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| Some(format!("ip_{:x}", request.relative_address)))
            .collect())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn check_cfi_source_byte_and_file_routes(name: &str, live_source: LiveCfiSource) {
    if let Some(data) = std::env::var_os("PYROCLAST_CFI_SOURCE_DATA") {
        let data = std::path::PathBuf::from(data);
        let expected =
            std::env::var("PYROCLAST_CFI_SOURCE_EXPECTED").expect("expected folded frames");
        let bytes = std::fs::read(&data).expect("recording bytes");
        assert_eq!(
            fold_perfdata_callchains_with_symbols(
                &bytes,
                FoldOptions::default(),
                &CfiAddressResolver
            )
            .expect("byte fold"),
            expected
        );
        assert_eq!(
            pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                &data,
                FoldOptions::default(),
                &CfiAddressResolver
            )
            .expect("file fold"),
            expected
        );
        return;
    }
    let fixture = cfi_source_fixture(live_source);
    let labels = fixture
        .expected_ips
        .iter()
        .rev()
        .map(|ip| format!("ip_{:x}", ip - 0x0040_0000))
        .collect::<Vec<_>>()
        .join(";");
    let expected = format!(":12;{labels} 1\n");
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", name, "--nocapture"])
        .env("HOME", &fixture.home)
        .env("PYROCLAST_CFI_SOURCE_DATA", &fixture.data)
        .env("PYROCLAST_CFI_SOURCE_EXPECTED", expected)
        .output()
        .expect("isolated byte/file routes");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn check_cfi_source_perf_script(live_source: LiveCfiSource) {
    let fixture = cfi_source_fixture(live_source);
    for symbolizer in ["addr2line", "rust-addr2line"] {
        let output = Command::new(env!("CARGO_BIN_EXE_pyroclast"))
            .args([
                "plumbing",
                "perf-script",
                "--no-inline",
                "--symbolizer",
                symbolizer,
            ])
            .arg(&fixture.data)
            .env("HOME", &fixture.home)
            .env("DEBUGINFOD_URLS", "")
            .output()
            .expect("public perf-script route");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let script = String::from_utf8(output.stdout).expect("script UTF-8");
        let ips = script
            .lines()
            .filter_map(|line| {
                line.split_whitespace()
                    .next()
                    .and_then(|word| u64::from_str_radix(word, 16).ok())
            })
            .collect::<Vec<_>>();
        assert_eq!(ips, fixture.expected_ips, "{symbolizer}: {script}");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn byte_and_file_routes_prefer_live_cfi_over_recorded_build_id_cache() {
    check_cfi_source_byte_and_file_routes(
        "byte_and_file_routes_prefer_live_cfi_over_recorded_build_id_cache",
        LiveCfiSource::WithCfi,
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn byte_and_file_routes_do_not_replace_valid_live_elf_without_cfi_with_cache() {
    check_cfi_source_byte_and_file_routes(
        "byte_and_file_routes_do_not_replace_valid_live_elf_without_cfi_with_cache",
        LiveCfiSource::WithoutCfi,
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn perf_script_prefers_live_cfi_over_recorded_build_id_cache() {
    check_cfi_source_perf_script(LiveCfiSource::WithCfi);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn perf_script_does_not_replace_valid_live_elf_without_cfi_with_cache() {
    check_cfi_source_perf_script(LiveCfiSource::WithoutCfi);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn byte_and_file_routes_use_cache_cfi_when_live_module_cannot_be_reported() {
    for source in [
        LiveCfiSource::Missing,
        LiveCfiSource::Invalid,
        LiveCfiSource::Unreadable,
        LiveCfiSource::NonRegular,
    ] {
        check_cfi_source_byte_and_file_routes(
            "byte_and_file_routes_use_cache_cfi_when_live_module_cannot_be_reported",
            source,
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn perf_script_uses_cache_cfi_when_live_module_cannot_be_reported() {
    for source in [
        LiveCfiSource::Missing,
        LiveCfiSource::Invalid,
        LiveCfiSource::Unreadable,
        LiveCfiSource::NonRegular,
    ] {
        check_cfi_source_perf_script(source);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug)]
enum UnwindReplacementMmap {
    Mmap,
    Mmap2,
    BuildId,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct UnwindReplacementFixture {
    root: tempfile::TempDir,
    home: std::path::PathBuf,
    data: std::path::PathBuf,
    expected_ips: [Vec<u64>; 3],
    replacement_base: u64,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn compile_unwind_replacement_elf(
    source: &std::path::Path,
    binary: &std::path::Path,
    cached: bool,
) {
    let output = Command::new("cc")
        .args([
            "-nostdlib",
            "-no-pie",
            "-Wl,-e,identity_leaf",
            "-Wl,-Ttext=0x401000",
            "-Wl,--eh-frame-hdr",
        ])
        .arg(if cached { "-DCACHE_CFI" } else { "-DLIVE_CFI" })
        .arg(if cached {
            "-Wl,--build-id=0x2222222222222222222222222222222222222222"
        } else {
            "-Wl,--build-id=0x1111111111111111111111111111111111111111"
        })
        .arg(source)
        .arg("-o")
        .arg(binary)
        .output()
        .expect("compile replacement ELF");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn unwind_replacement_record(
    form: UnwindReplacementMmap,
    path: &str,
    start: u64,
    id: u8,
    time: u64,
) -> Vec<u8> {
    let len = 0x0041_0000 - start;
    let (kind, misc, mut payload) = match form {
        UnwindReplacementMmap::Mmap => (
            1,
            PERF_RECORD_MISC_CPUMODE_USER,
            mmap_payload(11, 12, start, len, 0, path),
        ),
        UnwindReplacementMmap::Mmap2 => (
            10,
            PERF_RECORD_MISC_CPUMODE_USER,
            mmap2_payload(11, 12, start, len, 0, 5, path),
        ),
        UnwindReplacementMmap::BuildId => {
            let mut payload = mmap_range_payload(11, 12, start, len, 0);
            payload.extend([20, 0, 0, 0]);
            payload.extend([id; 20]);
            payload.extend(5_u32.to_le_bytes());
            payload.extend(2_u32.to_le_bytes());
            payload.extend(path.as_bytes());
            payload.push(0);
            (
                10,
                PERF_RECORD_MISC_CPUMODE_USER | PERF_RECORD_MISC_MMAP_BUILD_ID,
                payload,
            )
        }
    };
    payload.resize(payload.len().next_multiple_of(8), 0);
    payload.extend(11_u32.to_le_bytes());
    payload.extend(12_u32.to_le_bytes());
    payload.extend(time.to_le_bytes());
    record_bytes_with_misc(kind, misc, &payload)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn unwind_replacement_samples() -> [Vec<u8>; 3] {
    let mut stack = [0; 64];
    stack[..8].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[8..16].copy_from_slice(&0x0040_1041_u64.to_le_bytes());
    [1_000_000_000_u64, 3_000_000_000, 5_000_000_000].map(|time| {
        let mut payload = sample_payload_with_optional_timestamp(
            sample_payload_with_user_stack(
                0x0040_1001,
                11,
                12,
                [0xffff_ffff_ffff_fe00, 0x0040_1001],
                2,
                [0, 0x7000_0000, 0x0040_1001],
                stack,
            ),
            true,
        );
        put_u64(&mut payload, 16, time);
        record_bytes_with_misc(PERF_RECORD_SAMPLE, PERF_RECORD_MISC_CPUMODE_USER, &payload)
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn unwind_replacement_assembly() -> &'static str {
    r#".text
.globl identity_leaf
.type identity_leaf,@function
identity_leaf:
.cfi_startproc
#ifdef CACHE_CFI
.cfi_def_cfa %rsp,16
#else
.cfi_def_cfa %rsp,8
#endif
.cfi_offset %rip,-8
.fill 16,1,0x90
ret
.cfi_endproc
.size identity_leaf,.-identity_leaf
.p2align 5
.globl caller_live
.type caller_live,@function
caller_live:
.cfi_startproc
.cfi_def_cfa %rsp,8
.cfi_undefined %rip
.fill 16,1,0x90
ret
.cfi_endproc
.size caller_live,.-caller_live
.p2align 5
.globl caller_cache
.type caller_cache,@function
caller_cache:
.cfi_startproc
.cfi_def_cfa %rsp,8
.cfi_undefined %rip
.fill 16,1,0x90
ret
.cfi_endproc
.size caller_cache,.-caller_cache
.section .note.GNU-stack,"",@progbits
"#
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn unwind_replacement_fixture(
    vdso: bool,
    changed_base: bool,
    valid: bool,
    form: UnwindReplacementMmap,
) -> UnwindReplacementFixture {
    let root = tempfile::tempdir().expect("replacement fixture");
    let home = root.path().join("home");
    let old = if vdso {
        "[vdso]".to_string()
    } else {
        root.path().join("old-missing.elf").to_str().unwrap().into()
    };
    let id = "2222222222222222222222222222222222222222";
    let cached = pyroclast::symbols::perf_build_id_elf_path_for_dso(
        &home.join(".debug"),
        std::path::Path::new(&old),
        id,
    );
    std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
    let source = root.path().join("identity.S");
    std::fs::write(&source, unwind_replacement_assembly()).unwrap();
    compile_unwind_replacement_elf(&source, &cached, true);
    let bytes = std::fs::read(&cached).unwrap();
    let elf = object::File::parse(bytes.as_slice()).unwrap();
    assert_eq!(elf.kind(), object::ObjectKind::Executable);
    for (name, address) in [
        ("identity_leaf", 0x0040_1000),
        ("caller_live", 0x0040_1020),
        ("caller_cache", 0x0040_1040),
    ] {
        assert_eq!(
            elf.symbols()
                .find(|s| s.name() == Ok(name))
                .unwrap()
                .address(),
            address
        );
    }
    let replacement = root.path().join("replacement.elf");
    if valid {
        compile_unwind_replacement_elf(&source, &replacement, false);
    }
    let replacement_base = if changed_base {
        0x0040_1000
    } else {
        0x0040_0000
    };
    let data = root.path().join("perf.data");
    write_unwind_replacement_recording(&data, &old, &replacement, replacement_base, form);
    // Native lifecycle trace: the first changed-valid report succeeds, but its
    // fresh-FD callback re-report GCs it. Mapping back reuses the original CFI.
    let before = vec![0x0040_1001, 0x0040_1001, 0x0040_1040];
    let after = if changed_base {
        vec![0x0040_1001]
    } else {
        before.clone()
    };
    UnwindReplacementFixture {
        root,
        home,
        data,
        expected_ips: [before.clone(), after, before],
        replacement_base,
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_unwind_replacement_recording(
    data: &std::path::Path,
    old: &str,
    replacement: &std::path::Path,
    replacement_base: u64,
    form: UnwindReplacementMmap,
) {
    let mut attr = file_attr_bytes_with_regs(
        PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_CALLCHAIN
            | PERF_SAMPLE_REGS_USER
            | PERF_SAMPLE_STACK_USER,
        (1 << 6) | (1 << 7) | (1 << 8),
    );
    put_u64(&mut attr, 40, 1 << 18); // sample_id_all: keep replacement between samples.
    let [before, after, recovered] = unwind_replacement_samples();
    let records = [
        unwind_replacement_record(
            UnwindReplacementMmap::BuildId,
            old,
            0x0040_0000,
            0x22,
            500_000_000,
        ),
        before,
        unwind_replacement_record(
            form,
            replacement.to_str().unwrap(),
            replacement_base,
            0x11,
            2_000_000_000,
        ),
        after,
        unwind_replacement_record(form, old, 0x0040_0000, 0x22, 4_000_000_000),
        recovered,
    ];
    let mut build_id = u32::MAX.to_le_bytes().to_vec();
    build_id.extend([0x22; 20]);
    build_id.extend([0; 4]);
    build_id.extend(old.as_bytes());
    build_id.push(0);
    build_id.resize((8 + build_id.len()).next_multiple_of(8) - 8, 0);
    let build_id = record_bytes_with_misc(67, PERF_RECORD_MISC_CPUMODE_USER, &build_id);
    std::fs::write(
        data,
        perfdata_with_records_attrs_and_build_id_feature([attr], records, &build_id),
    )
    .unwrap();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn unwind_replacement_expected_fold(fixture: &UnwindReplacementFixture) -> String {
    use std::fmt::Write as _;

    let mut counts = std::collections::BTreeMap::<String, u64>::new();
    for (ips, base) in
        fixture
            .expected_ips
            .iter()
            .zip([0x0040_0000, fixture.replacement_base, 0x0040_0000])
    {
        let labels = ips
            .iter()
            .rev()
            .map(|ip| format!("ip_{:x}", ip - base))
            .collect::<Vec<_>>()
            .join(";");
        *counts.entry(format!(":12;{labels}")).or_default() += 1;
    }
    counts
        .into_iter()
        .fold(String::new(), |mut output, (stack, count)| {
            writeln!(output, "{stack} {count}").unwrap();
            output
        })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn check_unwind_replacement_byte_file_matrix(name: &str, vdso: bool, changed_base: bool) {
    if let Some(data) = std::env::var_os("PYROCLAST_UNWIND_REPLACEMENT_DATA") {
        let data = std::path::PathBuf::from(data);
        let expected = std::env::var("PYROCLAST_UNWIND_REPLACEMENT_FOLDED").unwrap();
        let bytes = std::fs::read(&data).unwrap();
        assert_eq!(
            fold_perfdata_callchains_with_symbols(
                &bytes,
                FoldOptions::default(),
                &CfiAddressResolver
            )
            .unwrap(),
            expected,
            "byte route"
        );
        assert_eq!(
            pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                &data,
                FoldOptions::default(),
                &CfiAddressResolver
            )
            .unwrap(),
            expected,
            "file route"
        );
        return;
    }
    for form in [
        UnwindReplacementMmap::Mmap,
        UnwindReplacementMmap::Mmap2,
        UnwindReplacementMmap::BuildId,
    ] {
        for valid in [false, true] {
            let fixture = unwind_replacement_fixture(vdso, changed_base, valid, form);
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("HOME", &fixture.home)
                .env("PYROCLAST_UNWIND_REPLACEMENT_DATA", &fixture.data)
                .env(
                    "PYROCLAST_UNWIND_REPLACEMENT_FOLDED",
                    unwind_replacement_expected_fold(&fixture),
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{form:?} valid={valid}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn check_unwind_replacement_perf_script_matrix(vdso: bool, changed_base: bool) {
    for form in [
        UnwindReplacementMmap::Mmap,
        UnwindReplacementMmap::Mmap2,
        UnwindReplacementMmap::BuildId,
    ] {
        for valid in [false, true] {
            let fixture = unwind_replacement_fixture(vdso, changed_base, valid, form);
            for symbolizer in ["addr2line", "rust-addr2line"] {
                let output = Command::new(env!("CARGO_BIN_EXE_pyroclast"))
                    .args([
                        "plumbing",
                        "perf-script",
                        "--no-inline",
                        "--symbolizer",
                        symbolizer,
                    ])
                    .arg(&fixture.data)
                    .env("HOME", &fixture.home)
                    .env("DEBUGINFOD_URLS", "")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let script = String::from_utf8(output.stdout).unwrap();
                let stacks = script
                    .trim()
                    .split("\n\n")
                    .map(|block| {
                        block
                            .lines()
                            .filter_map(|line| {
                                line.split_whitespace()
                                    .next()
                                    .and_then(|word| u64::from_str_radix(word, 16).ok())
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    stacks, fixture.expected_ips,
                    "{form:?} valid={valid} {symbolizer}: {script}"
                );
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn byte_file_ordinary_same_base_replacement_retains_cached_cfi() {
    check_unwind_replacement_byte_file_matrix(
        "byte_file_ordinary_same_base_replacement_retains_cached_cfi",
        false,
        false,
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn byte_file_ordinary_changed_base_replacement_rejects_fixed_elf() {
    check_unwind_replacement_byte_file_matrix(
        "byte_file_ordinary_changed_base_replacement_rejects_fixed_elf",
        false,
        true,
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn byte_file_vdso_changed_base_replacement_rejects_fixed_elf() {
    check_unwind_replacement_byte_file_matrix(
        "byte_file_vdso_changed_base_replacement_rejects_fixed_elf",
        true,
        true,
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn byte_file_vdso_same_base_replacement_retains_cached_cfi() {
    check_unwind_replacement_byte_file_matrix(
        "byte_file_vdso_same_base_replacement_retains_cached_cfi",
        true,
        false,
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn perf_script_ordinary_same_base_replacement_retains_cached_cfi() {
    check_unwind_replacement_perf_script_matrix(false, false);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn perf_script_ordinary_changed_base_replacement_rejects_fixed_elf() {
    check_unwind_replacement_perf_script_matrix(false, true);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn perf_script_vdso_changed_base_replacement_rejects_fixed_elf() {
    check_unwind_replacement_perf_script_matrix(true, true);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn perf_script_vdso_same_base_replacement_retains_cached_cfi() {
    check_unwind_replacement_perf_script_matrix(true, false);
}

#[test]
fn audit_regression_rejects_maximal_attr_section_before_allocation() {
    let mut bytes = perfdata_with_records_and_attrs([], []);
    put_u64(&mut bytes, 32, u64::MAX);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    assert!(fold_perfdata_file_with_options(file.path(), FoldOptions::default()).is_err());
    assert!(fold_perfdata_callchains(&bytes).is_err());
}

#[test]
fn audit_regression_rejects_overflowing_event_desc_range() {
    let mut bytes = perfdata_with_records_and_attrs([], []);
    put_u64(&mut bytes, 72, 1 << 12);
    bytes.extend(1_u64.to_le_bytes());
    bytes.extend(u64::MAX.to_le_bytes());
    assert!(summarize_perfdata(&bytes).is_err());
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    assert!(fold_perfdata_file_with_options(file.path(), FoldOptions::default()).is_err());
}

#[test]
fn audit_regression_rejects_overlapping_attr_and_data_sections() {
    let mut bytes = perfdata_with_records_and_attrs([file_attr_bytes(0, 0, 0)], []);
    put_u64(&mut bytes, 40, 112);
    put_u64(&mut bytes, 48, 8);
    // A structurally valid unknown record inside the attr's config word.
    put_u64(&mut bytes, 112, (8_u64 << 48) | 0x63);
    assert!(summarize_perfdata(&bytes).is_err());
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    assert!(fold_perfdata_file_with_options(file.path(), FoldOptions::default()).is_err());
}

#[test]
fn audit_regression_rejects_event_desc_counts_and_truncation() {
    let event_count = [u32::MAX.to_le_bytes(), 0_u32.to_le_bytes()].concat();
    let id_count = [
        1_u32.to_le_bytes(),
        0_u32.to_le_bytes(),
        u32::MAX.to_le_bytes(),
        0_u32.to_le_bytes(),
    ]
    .concat();
    for payload in [event_count, id_count] {
        let mut bytes = perfdata_with_records_and_attrs([], []);
        put_u64(&mut bytes, 72, 1 << 12);
        let payload_offset = bytes.len() + 16;
        bytes.extend(u64::try_from(payload_offset).unwrap().to_le_bytes());
        bytes.extend(u64::try_from(payload.len()).unwrap().to_le_bytes());
        bytes.extend(payload);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        assert!(summarize_perfdata(&bytes).is_err());
        assert!(fold_perfdata_file_with_options(file.path(), FoldOptions::default()).is_err());
        bytes.truncate(112);
        std::fs::write(file.path(), &bytes).unwrap();
        assert!(summarize_perfdata(&bytes).is_err());
        assert!(fold_perfdata_file_with_options(file.path(), FoldOptions::default()).is_err());
    }
}

#[test]
fn audit_regression_rejects_maximal_attr_id_range() {
    let bytes = perfdata_with_records_and_attrs([file_attr_bytes(0, 104, u64::MAX)], []);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    assert!(summarize_perfdata(&bytes).is_err());
    assert!(fold_perfdata_file_with_options(file.path(), FoldOptions::default()).is_err());
}

#[test]
fn audit_regression_summary_uses_recording_architecture_for_register_ip() {
    for (arch, mask, values, expected) in [
        ("x86_64", 1 << 8, vec![0x1111], Some(0x1111)),
        (
            "aarch64",
            (1 << 8) | (1 << 32),
            vec![0x8888, 0x3232],
            Some(0x3232),
        ),
        ("aarch64", 1 << 8, vec![0x8888], None),
    ] {
        let mut payload = sample_payload(0x1000, 11, 12, [0x1000]);
        payload.extend(2_u64.to_le_bytes());
        for value in values {
            payload.extend(u64::to_le_bytes(value));
        }
        let bytes = perfdata_with_records_attrs_and_arch_feature(
            [file_attr_bytes_with_regs(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER,
                mask,
            )],
            [record_bytes(9, &payload)],
            arch,
        );
        let summary = summarize_perfdata(&bytes).unwrap();
        assert_eq!(
            summary.sample_stacks[0].user_register_ip, expected,
            "{arch}"
        );
    }
}

#[test]
fn file_summary_preserves_sample_timestamps_and_cpu() {
    use pyroclast::perfdata::fold::summarize_perfdata_file;
    use pyroclast::perfdata::samples::PERF_SAMPLE_CPU;
    let mut payload = Vec::new();
    payload.extend(0x1000_u64.to_le_bytes());
    payload.extend(11_u32.to_le_bytes());
    payload.extend(12_u32.to_le_bytes());
    payload.extend(1_234_567_890_u64.to_le_bytes());
    payload.extend(7_u32.to_le_bytes());
    payload.extend(0_u32.to_le_bytes());
    payload.extend(1_u64.to_le_bytes());
    payload.extend(0x1000_u64.to_le_bytes());
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_TIME
                | PERF_SAMPLE_CPU
                | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(9, &payload)],
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    let memory = summarize_perfdata(&bytes).unwrap();
    assert_eq!(memory.sample_stacks[0].time, Some(1_234_567_890));
    assert_eq!(memory.sample_stacks[0].cpu, Some(7));
    assert_eq!(summarize_perfdata_file(file.path()).unwrap(), memory);
}

#[test]
fn audit_regression_summary_uses_the_event_default_period_when_payload_omits_it() {
    use pyroclast::perfdata::fold::summarize_perfdata_file;
    for default_period in [0_u64, 37] {
        let mut attr = file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        );
        put_u64(&mut attr, 16, default_period);
        let bytes = perfdata_with_records_and_attrs(
            [attr],
            [record_bytes(
                9,
                &sample_payload_with_time(0x1000, 11, 12, 100, [0x1000]),
            )],
        );
        let memory = summarize_perfdata(&bytes).unwrap();
        assert_eq!(memory.sample_stacks[0].period, Some(default_period));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        assert_eq!(summarize_perfdata_file(file.path()).unwrap(), memory);
        let profile = pyroclast::summary::summarize_perf_summary(&memory, 1000, 10).unwrap();
        assert_eq!(profile.weighted_samples, default_period);
        assert_eq!(profile.threads[0].weighted_samples, default_period);
        assert_eq!(profile.timeline.buckets[0].weighted_samples, default_period);
        assert_eq!(
            pyroclast::perfdata::analysis::analyze_perfdata(&bytes, 10)
                .unwrap()
                .weighted_samples,
            default_period
        );
    }
}

#[test]
fn bounded_file_profile_matches_retained_summary_for_unordered_and_untimed_samples() {
    for timed in [true, false] {
        let flags = PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_CALLCHAIN
            | if timed { PERF_SAMPLE_TIME } else { 0 };
        let mut attr = file_attr_bytes(flags, 0, 0);
        put_u64(&mut attr, 16, 37);
        let mut records = vec![
            record_bytes(3, &comm_payload(11, 12, "parent")),
            record_bytes(7, &fork_payload(11, 11, 13, 12, 0)),
        ];
        for (tid, time) in [(12, 3000), (13, 1000), (12, 1500), (13, 1000)] {
            let payload = if timed {
                sample_payload_with_time(0x1000, 11, tid, time, [0x1000])
            } else {
                sample_payload(0x1000, 11, tid, [0x1000])
            };
            records.push(record_bytes(9, &payload));
        }
        records.push(record_bytes(3, &comm_payload(11, 12, "renamed")));
        records.push(record_bytes(2, &lost_payload(1, 5)));
        let records: [Vec<u8>; 8] = records.try_into().unwrap();
        let bytes = perfdata_with_records_and_attrs([attr], records);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let expected = pyroclast::summary::summarize_perfdata_profile(&bytes, 1000, 10).unwrap();
        assert_eq!(
            pyroclast::summary::summarize_perfdata_profile_file(file.path(), 1000, 10).unwrap(),
            expected
        );
        assert_eq!(expected.threads[0].comm, "renamed");
        assert_eq!(expected.threads[1].comm, "parent");
        assert_eq!(expected.lost_records, 5);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_file_profile_storage_does_not_grow_with_repeated_samples() {
    use std::io::Write;
    if let Some(path) = std::env::var_os("PYROCLAST_SUMMARY_MEMORY_FIXTURE") {
        let summary = pyroclast::summary::summarize_perfdata_profile_file(
            std::path::Path::new(&path),
            1000,
            10,
        )
        .unwrap();
        let samples = std::env::var("PYROCLAST_SUMMARY_EXPECTED_SAMPLES")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(summary.total_samples, samples);
        assert_eq!(summary.weighted_samples, u64::try_from(samples).unwrap());
        assert_eq!(summary.threads[0].samples, samples);
        assert_eq!(summary.timeline.buckets[0].samples, samples);
        assert_eq!(summary.threads.len(), 1);
        assert_eq!(summary.timeline.buckets.len(), 1);
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let peak = status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .unwrap();
        println!(
            "summary_peak_rss_kib={}",
            peak.split_whitespace().nth(1).unwrap()
        );
        return;
    }
    let measure = |samples: u64| {
        let mut attr = file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        );
        put_u64(&mut attr, 16, 1);
        let record = record_bytes(
            9,
            &sample_payload_with_time(0x1000, 11, 12, 100, [0x1000; 128]),
        );
        let mut header = perfdata_with_records_and_attrs([attr], []);
        put_u64(
            &mut header,
            48,
            samples * u64::try_from(record.len()).unwrap(),
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = std::io::BufWriter::new(file.as_file());
        writer.write_all(&header).unwrap();
        for _ in 0..samples {
            writer.write_all(&record).unwrap();
        }
        writer.flush().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "bounded_file_profile_storage_does_not_grow_with_repeated_samples",
                "--nocapture",
            ])
            .env("PYROCLAST_SUMMARY_MEMORY_FIXTURE", file.path())
            .env("PYROCLAST_SUMMARY_EXPECTED_SAMPLES", samples.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("summary_peak_rss_kib="))
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    // Both recordings exceed the 4 MiB read window; the larger one has 24x as
    // many samples, identical threads/buckets, and ~200 MiB of repeated frames.
    let small_peak = measure(8192);
    let large_peak = measure(200_000);
    println!("bounded_summary_peak_rss small={small_peak}KiB large={large_peak}KiB");
    assert!(
        large_peak <= small_peak + 16 * 1024,
        "sample retention grew memory: small={small_peak} KiB large={large_peak} KiB"
    );
}

#[test]
fn audit_regression_summary_retains_metadata_without_callchain() {
    let flags = PERF_SAMPLE_IP
        | PERF_SAMPLE_TID
        | PERF_SAMPLE_PERIOD
        | PERF_SAMPLE_REGS_USER
        | PERF_SAMPLE_STACK_USER;
    for stack in [Vec::new(), vec![1, 2, 3, 4, 5, 6, 7, 8]] {
        let mut payload = sample_payload_with_period_no_callchain(0x1000, 11, 12, 7);
        payload.extend(2_u64.to_le_bytes());
        payload.extend(0xaaaa_u64.to_le_bytes());
        payload.extend(u64::try_from(stack.len()).unwrap().to_le_bytes());
        payload.extend(&stack);
        if !stack.is_empty() {
            payload.extend(u64::try_from(stack.len()).unwrap().to_le_bytes());
        }
        let bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes_with_regs(flags, 1 << 8)],
            [record_bytes(9, &payload)],
        );
        let summary = summarize_perfdata(&bytes).unwrap();
        let sample = &summary.sample_stacks[0];
        assert_eq!(sample.user_register_ip, Some(0xaaaa));
        assert_eq!(sample.user_register_count, 1);
        assert!(sample.has_user_stack);
        assert_eq!(sample.user_stack_size, stack.len());
        let analysis = pyroclast::perfdata::analysis::analyze_perfdata(&bytes, 10).unwrap();
        assert_eq!(analysis.user_register_samples, 1);
        assert_eq!(analysis.user_stack_samples, 1);
        assert_eq!(analysis.user_stack_bytes, stack.len());
        // Folding must keep perf's event-line IP behavior without DWARF callers.
        let ip_payload = sample_payload_with_period_no_callchain(0x1000, 11, 12, 7);
        let ip_bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD,
                0,
                0,
            )],
            [record_bytes(9, &ip_payload)],
        );
        assert_eq!(
            fold_perfdata_callchains(&bytes).unwrap(),
            fold_perfdata_callchains(&ip_bytes).unwrap()
        );
        payload.pop();
        let truncated = perfdata_with_records_and_attrs(
            [file_attr_bytes_with_regs(flags, 1 << 8)],
            [record_bytes(9, &payload)],
        );
        assert!(summarize_perfdata(&truncated).is_err());
    }
}

#[test]
fn file_and_bytes_do_not_apply_future_stream_build_ids_to_earlier_samples() {
    // perf session.c:1649 dispatches stream HEADER_BUILD_ID when encountered;
    // header.c:5232/__event_process_build_id updates that DSO, not past samples.
    use pyroclast::perfdata::fold::fold_perfdata_file_with_symbols;
    let attr = file_attr_bytes(
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
        0,
        0,
    );
    let mapping = record_bytes(10, &mmap2_payload(11, 12, 0x1000, 0x100, 0, 5, "/bin/app"));
    let sample = record_bytes(9, &sample_payload(0x1010, 11, 12, [0x1010]));
    for (header_id, stream_id) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut records = vec![mapping.clone(), sample.clone()];
        if stream_id {
            let mut event = build_id_event_payload(11, &[0xbb; 20], "/bin/app");
            event[4..6].copy_from_slice(&PERF_RECORD_MISC_CPUMODE_USER.to_le_bytes());
            records.push(event);
        }
        let mut bytes = perfdata_with_records_and_attrs_vec(vec![attr], records);
        if header_id {
            let mut payload = build_id_event_payload(11, &[0xaa; 20], "/bin/app");
            payload[4..6].copy_from_slice(&PERF_RECORD_MISC_CPUMODE_USER.to_le_bytes());
            put_u64(&mut bytes, 72, 1 << 2);
            let offset = bytes.len() + 16;
            bytes.extend(u64::try_from(offset).unwrap().to_le_bytes());
            bytes.extend(u64::try_from(payload.len()).unwrap().to_le_bytes());
            bytes.extend(payload);
        }
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let memory_resolver = RecordingSymbolResolver::default();
        let file_resolver = RecordingSymbolResolver::default();
        let options = FoldOptions::default();
        let memory =
            fold_perfdata_callchains_with_symbols(&bytes, options, &memory_resolver).unwrap();
        let disk = fold_perfdata_file_with_symbols(file.path(), options, &file_resolver).unwrap();
        assert_eq!(disk, memory);
        assert_eq!(
            file_resolver.calls(),
            memory_resolver.calls(),
            "header={header_id}, stream={stream_id}"
        );
        let requests = memory_resolver.calls();
        assert!(!requests.is_empty());
        assert_eq!(
            requests[0][0].build_id,
            if header_id {
                Some("aa".repeat(20))
            } else {
                None
            }
        );
    }
}

#[test]
fn file_and_bytes_ignore_build_id_records_with_invalid_cpu_mode_like_perf() {
    // header.c:__event_process_build_id rejects misc=0 in its cpumode switch.
    let attr = file_attr_bytes(
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
        0,
        0,
    );
    let mut stream = build_id_event_payload(11, &[0xbb; 20], "/bin/app");
    stream[4..6].copy_from_slice(&0_u16.to_le_bytes());
    let mut feature = build_id_event_payload(11, &[0xaa; 20], "/bin/app");
    feature[4..6].copy_from_slice(&0_u16.to_le_bytes());
    let records = [
        stream,
        record_bytes(10, &mmap2_payload(11, 12, 0x1000, 0x100, 0, 5, "/bin/app")),
        record_bytes(9, &sample_payload(0x1010, 11, 12, [0x1010])),
    ];
    let bytes = perfdata_with_records_attrs_and_build_id_feature([attr], records, &feature);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    for file_route in [false, true] {
        let resolver = RecordingSymbolResolver::default();
        if file_route {
            pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                file.path(),
                FoldOptions::default(),
                &resolver,
            )
            .unwrap();
        } else {
            fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
                .unwrap();
        }
        assert_eq!(resolver.calls()[0][0].build_id, None);
    }
}

#[test]
fn summarizes_record_counts_and_comm_names() {
    let bytes = perfdata_with_records_and_attrs(
        [],
        [
            record_bytes(3, &comm_payload(1, 2, "sftp-s3")),
            record_bytes(
                1,
                &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/usr/bin/sftp-s3"),
            ),
            record_bytes(
                10,
                &mmap2_payload(1, 2, 0x3000, 0x4000, 0, 5, "/usr/lib/libc.so"),
            ),
            record_bytes(9, b"sample"),
        ],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.total_records, 4);
    assert_eq!(summary.record_count(1), 1);
    assert_eq!(summary.record_count(3), 1);
    assert_eq!(summary.record_count(9), 1);
    assert_eq!(summary.record_count(10), 1);
    assert_eq!(summary.comms, vec!["sftp-s3"]);
    assert_eq!(summary.mmaps, vec!["/usr/bin/sftp-s3", "/usr/lib/libc.so"]);
}

#[test]
fn summarizes_lost_record_counts() {
    let bytes = perfdata_with_records_and_attrs(
        [],
        [
            record_bytes(2, &lost_payload(7, 10)),
            record_bytes(2, &lost_payload(8, 20)),
        ],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.record_count(2), 2);
    assert_eq!(summary.lost_records, 30);
}

#[test]
fn summarizes_lost_sample_record_counts() {
    let bytes = perfdata_with_records_and_attrs([], [record_bytes(13, &42u64.to_le_bytes())]);

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.record_count(13), 1);
    assert_eq!(summary.lost_records, 42);
}

#[test]
fn summarizes_sample_callchain_counts_using_file_attr_layout() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0x2000, 0x3000]),
        )],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.sample_stacks.len(), 1);
    assert_eq!(summary.sample_stacks[0].callchain, vec![0x2000, 0x3000]);
}

#[test]
fn summarizes_dwarf_user_stack_payloads() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            1 << 8,
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(0x1000, 11, 12, [0x2000], 1, [0xaaaa], [1, 2, 3]),
        )],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.sample_stacks.len(), 1);
    assert_eq!(
        summary.sample_stacks[0].misc,
        PERF_RECORD_MISC_CPUMODE_KERNEL
    );
    assert_eq!(
        summary.sample_stacks[0].cpumode,
        PERF_RECORD_MISC_CPUMODE_KERNEL
    );
    assert!(summary.sample_stacks[0].has_user_stack);
    assert_eq!(summary.sample_stacks[0].user_register_count, 1);
    assert_eq!(summary.sample_stacks[0].user_register_ip, Some(0xaaaa));
    assert_eq!(summary.sample_stacks[0].user_stack_size, 3);
    assert_eq!(summary.sample_stacks[0].user_stack_dynamic_size, 3);
}

#[test]
fn skips_dwarf_unwind_when_sampled_ip_has_no_mapping_like_perf_libdw() {
    // perf's libdw path produces no accepted frame callbacks without a module
    // for the initial sampled IP, even when regs and stack bytes are present.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn skips_aarch64_dwarf_unwind_when_sampled_ip_has_no_mapping_like_perf_libdw() {
    // With no mapping for the initial sampled IP, perf never reaches an
    // accepted libdw frame callback; register contents cannot create frames.
    let mask = (1_u64 << 29) | (1_u64 << 30) | (1_u64 << 31) | (1_u64 << 32);
    let bytes = perfdata_with_records_attrs_and_arch_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            mask,
        )],
        [record_bytes(
            9,
            // Registers are in ascending perf-register order: fp, lr, sp, pc.
            // sp = 0x1000, fp = 0x1010: the fp chain record at fp+0 (next fp)
            // and fp+8 (next lr) are both zero, so the lr-derived caller is the
            // only unwound frame.
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [],
                1,
                [0x1010, 0x5000, 0x1000, 0x4000],
                [0_u8; 0x40],
            ),
        )],
        "aarch64",
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_when_mapped_object_cannot_be_loaded_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/missing-app"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_but_keeps_kernel_callchain_when_object_cannot_be_loaded_like_perf_script()
{
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/missing-app"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [
                        0xffff_ffff_ffff_fe00,
                        0xffff_ffff_8100_0000,
                        0xffff_ffff_8200_0000,
                    ],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn drops_dwarf_user_stack_when_current_object_is_missing_even_if_other_modules_loaded_like_perf_script()
 {
    let current_exe = std::env::current_exe().expect("current exe");
    let current_exe = current_exe.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x8000, 0x100, 0, current_exe.as_ref()),
            ),
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/missing-app"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [
                        0xffff_ffff_ffff_fe00,
                        0xffff_ffff_8100_0000,
                        0xffff_ffff_8200_0000,
                    ],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn drops_dwarf_user_stack_when_current_mapping_replaces_broad_loaded_mapping_like_perf_script() {
    let current_exe = std::env::current_exe().expect("current exe");
    let current_exe = current_exe.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x3000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4800, 0x1000, 0, "/tmp/missing-app"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4900,
                    11,
                    12,
                    [
                        0xffff_ffff_ffff_fe00,
                        0xffff_ffff_8100_0000,
                        0xffff_ffff_8200_0000,
                    ],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4900],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x49, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn keeps_rbp_caller_when_newer_mapping_overlaps_before_first_report_like_perf_script() {
    // perf's libdw module reporting is lazy: tools/perf/util/unwind-libdw.c
    // does not call report_module() until a sample enters the unwind path.
    // Overlapping MMAP records before that first report update the maps, but
    // there is no prior DWFL module yet for the later mapping to conflict with.
    // No FDE covers the sampled PC, so libdw reads [RBP+8] and emits 0x1233.
    // That caller is unmapped and remains an [unknown] frame.
    let current_exe = std::env::current_exe().expect("current exe");
    let current_exe = current_exe.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x1000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4800, 0x1000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4900,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4900],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x49, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[unknown];[{}] 1\n", current_exe_file_name());

    assert_eq!(folded, expected);
}

#[test]
fn skips_unwind_when_build_id_mapping_cannot_report_initial_module_like_perf_script() {
    // The recorded build-id mappings do not let perf report this initial
    // module, so libdw aborts before emitting an unwind entry.
    let current_exe = std::env::current_exe().expect("current exe");
    let current_exe = current_exe.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                23,
                &mmap2_build_id_payload(11, 11, 0x4000, 0x3000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                23,
                &mmap2_build_id_payload(11, 11, 0x4800, 0x1000, 0x1000, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4900,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4900],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x49, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn keeps_rbp_caller_when_header_build_id_mmap2_overlaps_before_first_report_like_perf_script() {
    // Header FEATURE_BUILD_ID resolution also happens when the mapping is
    // reported to DWFL. Without a sample before the overlap, there is no prior
    // reported module to reject this mapping.
    // The sampled PC has no covering FDE; [RBP+8] recovers caller 0x1233.
    // entry() retains that caller even though no recorded mapping covers it.
    let build_id = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
        0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
    ];
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_attrs_and_build_id_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x4000, 0x3000, 0, 5, current_exe.as_ref()),
            ),
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x4800, 0x1000, 0x1000, 5, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4900,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4900],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x49, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
        &build_id_event_payload(u32::MAX, &build_id, current_exe.as_ref()),
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[unknown];[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

#[test]
fn folds_recorded_callchain_only_without_initial_module_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [0x9000, 0xa000],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn skips_unmapped_user_unwind_frames_and_keeps_recorded_callchain_like_perf_script() {
    // perf's libdw entry path reports unwind frames with
    // thread__find_symbol(..., PERF_RECORD_MISC_USER, ip). If that lookup finds
    // no DSO, __report_module() returns success and unwind_entry() later keeps
    // the unresolved frame unless hide_unresolved is set.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [0x9000],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0, 0, 0, 0x81, 0xff, 0xff, 0xff, 0xff,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn uses_recorded_kernel_callchain_only_without_initial_module_with_user_marker() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_fe00,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn uses_recorded_callchain_only_without_initial_module_for_user_sample() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_ff80,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn uses_recorded_kernel_callchain_only_without_initial_module_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_ff80,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn keeps_kernel_user_context_without_dwarf_callers_when_initial_module_is_missing() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_fe00,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                    0x4000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_kernel_user_frames_without_dwarf_callers_when_initial_module_is_missing() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [0xffff_ffff_8100_0000, 0xffff_ffff_8200_0000, 0x4000],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_mixed_callchain_without_dwarf_callers_when_initial_module_is_missing() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [0xffff_ffff_8100_0000, 0xffff_ffff_8200_0000, 0x4000],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn skips_kernel_sample_unwind_without_initial_module_like_perf_libdw() {
    // A present-but-empty kernel callchain still cannot produce user unwind
    // entries when the user sampled IP has no reportable module.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn skips_dwarf_unwind_when_perf_user_stack_dynamic_size_is_zero_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_zero_dynamic_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_ff80,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn skips_unwind_with_short_stack_when_sampled_ip_is_unmapped() {
    let mut sample = sample_payload(
        0x4000,
        11,
        12,
        [
            0xffff_ffff_ffff_ff80,
            0xffff_ffff_8100_0000,
            0xffff_ffff_8200_0000,
        ],
    );
    append_user_stack_payload(
        &mut sample,
        1,
        [0x7fff_0008, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
        8,
    );
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample,
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn keeps_rbp_caller_for_mapped_dwarf_user_stack_like_perf_libdw() {
    // libdw emits the initial frame, then uses RBP when no FDE covers its PC.
    // The broad mapping labels both the initial IP and caller with this DSO.
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0, 0x1000_0000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[{0}];[{0}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_vdso_dwarf_leaf_is_not_dropped_without_build_id_metadata() {
    use inferno::collapse::Collapse;
    let mut bytes = x86_leaf_only_perfdata("[vdso]", [0x7ffe_ff00, 0x7fff_0000, 0x400], [0; 24]);
    put_u64(&mut bytes, 16, 144);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    let native = Command::new("perf")
        .args(["script", "--force", "--inline", "-i"])
        .arg(file.path())
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let mut expected = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(std::io::Cursor::new(native.stdout), &mut expected)
        .unwrap();
    let expected = String::from_utf8(expected).unwrap();
    assert!(
        !expected.is_empty(),
        "native perf retains the sampled vDSO leaf"
    );
    assert!(expected.contains("vdso"), "{expected}");
    assert_eq!(fold_perfdata_callchains(&bytes).unwrap(), expected);
    assert_eq!(
        fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
        expected
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn kernel_only_recorded_chain_uses_user_maps_and_current_cfi_row_like_native_perf() {
    // libdwfl/frame_unwind.c:529-675 evaluates the row at the current PC;
    // perf unwind-libdw.c:314-338 retains an unmapped return PC minus one.
    // A later DW_CFA_undefined must not affect the earlier row.
    let fixture = SyntheticX86_64Object::create_with_stack_cfi();
    let mut elf = std::fs::read(&fixture.path).unwrap();
    elf[0x124..0x128].copy_from_slice(&8_u32.to_le_bytes());
    elf[0x129..0x12c].copy_from_slice(&[0x44, 0x07, 16]);
    std::fs::write(&fixture.path, elf).unwrap();
    let (startup, entry) = SyntheticX86_64Object::create_compiled_startup();
    for (path, linked_ip, has_caller) in [
        (fixture.path.as_path(), 0x100_u64, true),
        (fixture.path.as_path(), 0x103, true),
        (fixture.path.as_path(), 0x104, false),
        (fixture.path.as_path(), 0x107, false),
        (startup.path.as_path(), entry, true),
    ] {
        for kernel_mapping in [false, true] {
            let base = 0x5555_0000;
            let ip = base + linked_ip;
            let mut mmap = mmap_payload(11, 12, base, 0x10000, 0, &path.to_string_lossy());
            mmap.resize(mmap.len().next_multiple_of(8), 0);
            let mut records = Vec::new();
            if kernel_mapping {
                let mut kernel = mmap_payload(u32::MAX, 0, 0, 0x2000, 0, "[kernel-test]");
                kernel.resize(kernel.len().next_multiple_of(8), 0);
                records.push(record_bytes_with_misc(
                    1,
                    PERF_RECORD_MISC_CPUMODE_KERNEL,
                    &kernel,
                ));
            }
            records.extend([
                record_bytes(1, &mmap),
                record_bytes_with_misc(
                    9,
                    PERF_RECORD_MISC_CPUMODE_KERNEL,
                    &sample_payload_with_user_stack(
                        0xffff_ffff_8100_0000,
                        11,
                        12,
                        [0xffff_ffff_ffff_ff80, 0xffff_ffff_8100_0000],
                        1,
                        [0, 0x7fff_0000, ip],
                        3_u64.to_le_bytes(),
                    ),
                ),
            ]);
            let mut bytes = perfdata_with_records_and_attrs_vec(
                vec![file_attr_bytes_with_regs(
                    PERF_SAMPLE_IP
                        | PERF_SAMPLE_TID
                        | PERF_SAMPLE_CALLCHAIN
                        | PERF_SAMPLE_REGS_USER
                        | PERF_SAMPLE_STACK_USER,
                    (1 << 6) | (1 << 7) | (1 << 8),
                )],
                records,
            );
            put_u64(&mut bytes, 16, 144);
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), &bytes).unwrap();
            let (script, expected) = native_script_and_fold(&bytes);
            assert_eq!(script.contains("2 [unknown]"), has_caller, "{script}");
            assert!(!expected.is_empty());
            let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(
                pyroclast::symbols::RustAddr2lineResolver::new(),
            );
            let options = FoldOptions {
                inline: true,
                count_periods: false,
            };
            assert_eq!(
                fold_perfdata_callchains_with_symbols(&bytes, options, &resolver).unwrap(),
                expected,
                "ip={ip:x}"
            );
            assert_eq!(
                pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                    file.path(),
                    options,
                    &resolver
                )
                .unwrap(),
                expected,
                "ip={ip:x}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn extends_recorded_kernel_user_callchain_with_dwarf_frames_like_native_perf() {
    use inferno::collapse::Collapse;

    // machine.c __thread__resolve_callchain() appends the register/stack
    // unwind after the recorded callchain, even when it contains user PCs.
    // unwind-libdw.c frame_callback() also retains the unmapped caller.
    let fixture = SyntheticX86_64Object::create();
    for (fixture, ip, bp, return_slot, caller) in [
        (fixture, 0x4000_u64, 0, 16, 0x1233_u64),
        (
            SyntheticX86_64Object::create(),
            0x4000,
            0x7fff_0008,
            16,
            0x1233,
        ),
        (
            SyntheticX86_64Object::create_with_stack_cfi(),
            0x100,
            0,
            0,
            0x102,
        ),
    ] {
        let base = ip & !0xfff;
        let mut mmap = mmap_payload(11, 12, base, 0x1000, base, &fixture.path_string());
        mmap.resize(mmap.len().next_multiple_of(8), 0);
        let mut stack = [0; 24];
        stack[return_slot..return_slot + 8].copy_from_slice(&(caller + 1).to_le_bytes());
        let mut bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes_with_regs(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_CALLCHAIN
                    | PERF_SAMPLE_REGS_USER
                    | PERF_SAMPLE_STACK_USER,
                (1 << 6) | (1 << 7) | (1 << 8),
            )],
            [
                record_bytes(1, &mmap),
                record_bytes_with_misc(
                    9,
                    PERF_RECORD_MISC_CPUMODE_KERNEL,
                    &sample_payload_with_user_stack(
                        0xffff_ffff_8100_0000,
                        11,
                        12,
                        [
                            0xffff_ffff_ffff_ff80,
                            0xffff_ffff_8100_0000,
                            0xffff_ffff_ffff_fe00,
                            ip,
                        ],
                        1,
                        [bp, 0x7fff_0000, ip],
                        stack,
                    ),
                ),
            ],
        );
        put_u64(&mut bytes, 16, 144);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let native = Command::new("perf")
            .args(["script", "--force", "--no-inline", "-i"])
            .arg(file.path())
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        let script = String::from_utf8(native.stdout).unwrap();
        assert_eq!(
            script.contains(&format!("{caller:x} [unknown]")),
            bp != 0 || ip == 0x100,
            "{script}"
        );
        assert_eq!(
            script.matches(&format!("{ip:x} [unknown]")).count(),
            2,
            "native retains both the recorded and unwound leaf: {script}"
        );
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::default()
            .collapse(std::io::Cursor::new(script), &mut expected)
            .unwrap();
        let expected = String::from_utf8(expected).unwrap();
        assert!(!expected.is_empty());
        assert_eq!(fold_perfdata_callchains(&bytes).unwrap(), expected);
        assert_eq!(
            fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
            expected
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn attached_thread_keeps_unmapped_initial_pc_like_native_perf_libdw() {
    // unwind-libdw.c:79-85 succeeds with no user DSO; :377-408 reuses the
    // existing DWFL attachment. dwfl_frame.c delivers the initial callback.
    let fixture = SyntheticX86_64Object::create();
    for unmapped_first in [false, true] {
        for tid in [12, 13] {
            let mut mmap = mmap_payload(11, 12, 0x4000, 0x1000, 0x4000, &fixture.path_string());
            mmap.resize(mmap.len().next_multiple_of(8), 0);
            let sample = |tid, ip| {
                record_bytes_with_misc(
                    9,
                    PERF_RECORD_MISC_CPUMODE_USER,
                    &sample_payload_with_user_stack(
                        ip,
                        11,
                        tid,
                        [],
                        1,
                        [0, 0x7fff_0000, ip],
                        [0; 24],
                    ),
                )
            };
            let mut records = vec![record_bytes(1, &mmap)];
            if unmapped_first {
                records.push(sample(12, 0x20000));
            }
            records.extend([sample(12, 0x4000), sample(tid, 0x20000)]);
            let bytes = perfdata_with_records_and_attrs_vec(
                vec![file_attr_bytes_with_regs(
                    PERF_SAMPLE_IP
                        | PERF_SAMPLE_TID
                        | PERF_SAMPLE_CALLCHAIN
                        | PERF_SAMPLE_REGS_USER
                        | PERF_SAMPLE_STACK_USER,
                    (1 << 6) | (1 << 7) | (1 << 8),
                )],
                records,
            );
            let (script, expected) = native_script_and_fold(&bytes);
            assert_eq!(script.contains("20000 [unknown]"), tid == 12, "{script}");
            assert!(!expected.is_empty());
            assert_eq!(
                fold_perfdata_callchains(&bytes).unwrap(),
                expected,
                "{script}"
            );
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), &bytes).unwrap();
            assert_eq!(
                fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
                expected,
                "{script}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn attached_aarch64_unmapped_pc_keeps_lr_caller_like_native_perf_libdw() {
    // unwind-libdw.c:79-85 accepts a missing user DSO. After attachment,
    // elfutils backends/aarch64_unwind.c:52-87 accepts LR before nonfatal
    // FP reads, even when the current PC is outside every module.
    let fixture = SyntheticAarch64Object::create_with_symbol();
    let mut mmap = mmap_payload(11, 11, 0x4000, 0x1000, 0x4000, &fixture.path_string());
    mmap.resize(mmap.len().next_multiple_of(8), 0);
    let sample = |pc, lr| {
        record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_user_stack(pc, 11, 11, [], 1, [0, lr, 0x1000, pc], [0; 24]),
        )
    };
    let bytes = perfdata_with_records_attrs_and_arch_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 29) | (1 << 30) | (1 << 31) | (1 << 32),
        )],
        [
            record_bytes(1, &mmap),
            sample(0x4000, 0),
            sample(0x20000, 0x30000),
        ],
        "aarch64",
    );
    let (script, expected) = native_script_and_fold(&bytes);
    assert!(script.contains("seed+0x0"), "{script}");
    assert!(script.contains("20000 [unknown]"), "{script}");
    assert!(script.contains("2ffff [unknown]"), "{script}");
    assert!(!expected.is_empty());
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(
        pyroclast::symbols::RustAddr2lineResolver::new(),
    );
    assert_eq!(
        fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver).unwrap(),
        expected,
        "{script}"
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    assert_eq!(
        pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
            file.path(),
            FoldOptions::default(),
            &resolver
        )
        .unwrap(),
        expected,
        "{script}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn aarch64_cfi_undefined_lr_stops_like_native_perf_libdw() {
    assert_aarch64_cfi_return_address_like_native(&[0x07, 0x1e], None);
}

#[cfg(target_os = "linux")]
#[test]
fn aarch64_cfi_zero_lr_stops_like_native_perf_libdw() {
    assert_aarch64_cfi_return_address_like_native(&[0x9e, 0], Some(0));
}

#[cfg(target_os = "linux")]
#[test]
fn aarch64_cfi_unreadable_lr_stops_like_native_perf_libdw() {
    assert_aarch64_cfi_return_address_like_native(&[0x9e, 4], None);
}

#[cfg(target_os = "linux")]
#[test]
fn aarch64_cfi_restored_lr_produces_caller_like_native_perf_libdw() {
    assert_aarch64_cfi_return_address_like_native(&[0x9e, 0], Some(0x30000));
}

#[cfg(target_os = "linux")]
#[test]
fn aarch64_cfi_pc_does_not_define_register_32_like_native_perf_libdw() {
    // frame_unwind.c:578 and 643 keep recovered register validity separate
    // from unwound->pc. The second FDE cannot use an explicitly undefined r32.
    let fixture = SyntheticAarch64Object::create_with_symbol();
    let mut object = std::fs::read(&fixture.path).unwrap();
    object.copy_within(0x100..0x130, 0x800);
    put_u32(&mut object, 0x820, 0x4000 - 0x820);
    object[0x829..0x82e].copy_from_slice(&[0x0c, 0x1f, 0, 0x07, 0x20]);
    put_u32(&mut object, 0x830, 20);
    put_u32(&mut object, 0x834, 0x34);
    put_u32(&mut object, 0x838, 0x4ffc - 0x838);
    put_u32(&mut object, 0x83c, 4);
    object[0x841..0x847].copy_from_slice(&[0x0c, 0x1f, 0, 0x09, 0x1e, 0x20]);
    for offset in [16, 24] {
        put_u64(&mut object, 0x2c0 + offset, 0x800);
    }
    put_u64(&mut object, 0x2c0 + 32, 76);
    std::fs::write(&fixture.path, object).unwrap();
    let mut mmap = mmap_payload(11, 11, 0x4000, 0x2000, 0x4000, &fixture.path_string());
    mmap.resize(mmap.len().next_multiple_of(8), 0);
    let bytes = perfdata_with_records_attrs_and_arch_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 29) | (1 << 30) | (1 << 31) | (1 << 32),
        )],
        [
            record_bytes(1, &mmap),
            record_bytes_with_misc(
                9,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    11,
                    [],
                    1,
                    [0, 0x5000, 0x1000, 0x4000],
                    [0; 24],
                ),
            ),
        ],
        "aarch64",
    );
    let (script, expected) = native_script_and_fold(&bytes);
    assert!(script.contains("4000 seed+0x0"), "{script}");
    assert_eq!(
        script
            .lines()
            .filter(|line| line.trim_start().starts_with("4fff "))
            .count(),
        1,
        "{script}"
    );
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(
        pyroclast::symbols::RustAddr2lineResolver::new(),
    );
    assert_eq!(
        fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver).unwrap(),
        expected,
        "{script}",
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    assert_eq!(
        pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
            file.path(),
            FoldOptions::default(),
            &resolver,
        )
        .unwrap(),
        expected,
        "{script}",
    );
}

#[cfg(target_os = "linux")]
fn assert_aarch64_cfi_return_address_like_native(rule: &[u8], recovered: Option<u64>) {
    // elfutils frame_unwind.c:529-675 retains a decoded CFI successor even
    // when RA is undefined, zero, or unreadable. Lines 741-760 return without
    // ebl_unwind in that case; the sampled LR cannot replace the recovered RA.
    let fixture = SyntheticAarch64Object::create_with_symbol();
    let mut object = std::fs::read(&fixture.path).unwrap();
    put_u32(&mut object, 0x120, 0x4000 - 0x120); // FDE pcrel start
    object[0x129..0x12c].copy_from_slice(&[0x0c, 0x1f, 0]); // CFA = SP
    object[0x12c..0x12c + rule.len()].copy_from_slice(rule);
    std::fs::write(&fixture.path, object).unwrap();
    let mut mmap = mmap_payload(11, 11, 0x4000, 0x1000, 0x4000, &fixture.path_string());
    mmap.resize(mmap.len().next_multiple_of(8), 0);
    let mut stack = [0; 24];
    stack[..8].copy_from_slice(&recovered.unwrap_or(0_u64).to_le_bytes());
    let sample = record_bytes_with_misc(
        9,
        PERF_RECORD_MISC_CPUMODE_USER,
        &sample_payload_with_user_stack(0x4000, 11, 11, [], 1, [0, 0x30000, 0x1000, 0x4000], stack),
    );
    let bytes = perfdata_with_records_attrs_and_arch_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 29) | (1 << 30) | (1 << 31) | (1 << 32),
        )],
        [record_bytes(1, &mmap), sample],
        "aarch64",
    );
    let (script, expected) = native_script_and_fold(&bytes);
    assert!(script.contains("4000 seed+0x0"), "{script}");
    assert_eq!(
        script.contains("2ffff [unknown]"),
        recovered == Some(0x30000),
        "{script}"
    );
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(
        pyroclast::symbols::RustAddr2lineResolver::new(),
    );
    assert_eq!(
        fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver).unwrap(),
        expected,
        "CFI {rule:?}, recovered {recovered:?}: {script}"
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    assert_eq!(
        pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
            file.path(),
            FoldOptions::default(),
            &resolver,
        )
        .unwrap(),
        expected,
        "CFI {rule:?}, recovered {recovered:?}: {script}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn shared_process_unwind_attachment_keeps_first_tid_like_native_perf_libdw() {
    // unwind-libdw.c stores DWFL on shared maps and next_thread() enumerates
    // only dwfl_pid(). dwfl_frame.c rejects reattachment and reports ESRCH
    // for another TID. This is an attachment lifetime, not a worker-name rule.
    let fixture = SyntheticX86_64Object::create();
    for recorded in [false, true] {
        for first_tid in [12, 13] {
            let other_tid = if first_tid == 12 { 13 } else { 12 };
            let mut mmap = mmap_payload(11, 11, 0, 0x10000, 0, &fixture.path_string());
            mmap.resize(mmap.len().next_multiple_of(8), 0);
            let sample = |pid, tid| {
                let mut payload = if recorded {
                    sample_payload(0x4000, pid, tid, [0x4000])
                } else {
                    sample_payload(0x4000, pid, tid, [])
                };
                append_user_stack_payload(&mut payload, 1, [0, 0x7fff_0000, 0x4000], [0; 24], 24);
                record_bytes_with_misc(9, PERF_RECORD_MISC_CPUMODE_USER, &payload)
            };
            let mut bytes = perfdata_with_records_and_attrs(
                [file_attr_bytes_with_regs(
                    PERF_SAMPLE_IP
                        | PERF_SAMPLE_TID
                        | PERF_SAMPLE_CALLCHAIN
                        | PERF_SAMPLE_REGS_USER
                        | PERF_SAMPLE_STACK_USER,
                    (1 << 6) | (1 << 7) | (1 << 8),
                )],
                [
                    record_bytes(1, &mmap),
                    record_bytes(PERF_RECORD_FORK, &fork_payload(11, 11, first_tid, 11, 0)),
                    sample(11, first_tid),
                    // A newly forked thread shares the already attached maps.
                    record_bytes(
                        PERF_RECORD_FORK,
                        &fork_payload(11, 11, other_tid, first_tid, 0),
                    ),
                    sample(11, other_tid),
                    sample(11, first_tid),
                    // A new process copies maps, not its parent's attachment.
                    record_bytes(PERF_RECORD_FORK, &fork_payload(22, 11, 22, first_tid, 0)),
                    sample(22, 22),
                ],
            );
            put_u64(&mut bytes, 16, 144);
            let (script, expected) = native_script_and_fold(&bytes);
            let label = format!("[{}]", fixture.file_name());
            let frames = if recorded {
                format!("{label};{label}")
            } else {
                label.clone()
            };
            let mut expected_rows = vec![
                format!(":{first_tid};{frames} 2\n"),
                format!(":22;{frames} 1\n"),
            ];
            if recorded {
                expected_rows.push(format!(":{other_tid};{label} 1\n"));
            }
            expected_rows.sort();
            assert_eq!(expected, expected_rows.concat(), "{script}");
            assert_eq!(
                fold_perfdata_callchains(&bytes).unwrap(),
                expected,
                "{script}"
            );
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), &bytes).unwrap();
            assert_eq!(
                fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
                expected
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn leader_exit_splits_surviving_and_new_thread_maps_like_native_perf() {
    let fixture = SyntheticX86_64Object::create();
    let replacement = SyntheticX86_64Object::create();
    let new_path = replacement.path.with_file_name("new-x86-64");
    std::fs::copy(&replacement.path, &new_path).unwrap();
    for keep_exited in [false, true] {
        let mmap = |tid, path: &str| {
            let mut payload = mmap_payload(11, tid, 0, 0x10000, 0, path);
            payload.resize(payload.len().next_multiple_of(8), 0);
            record_bytes(1, &payload)
        };
        let sample = |tid| {
            record_bytes_with_misc(
                9,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    tid,
                    [],
                    1,
                    [0, 0x7fff_0000, 0x4000],
                    [0; 24],
                ),
            )
        };
        let mut bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes_with_regs(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_CALLCHAIN
                    | PERF_SAMPLE_REGS_USER
                    | PERF_SAMPLE_STACK_USER,
                (1 << 6) | (1 << 7) | (1 << 8),
            )],
            [
                mmap(11, &fixture.path_string()),
                record_bytes(PERF_RECORD_FORK, &fork_payload(11, 11, 12, 11, 0)),
                sample(12),
                record_bytes(4, &fork_payload(11, 11, 11, 11, 0)),
                record_bytes(PERF_RECORD_FORK, &fork_payload(11, 11, 13, 12, 0)),
                mmap(13, new_path.to_str().unwrap()),
                sample(13),
                sample(12),
            ],
        );
        put_u64(&mut bytes, 16, 144);
        if keep_exited {
            // HEADER_AUXTRACE: an empty native auxtrace index is sufficient for
            // session.c to retain exited threads without synthetic AUX samples.
            put_u64(&mut bytes, 72, 1 << 18);
            let offset = u64::try_from(bytes.len()).unwrap() + 16;
            bytes.extend(offset.to_le_bytes());
            bytes.extend(8_u64.to_le_bytes());
            bytes.extend(0_u64.to_le_bytes());
        }
        let (script, expected) = native_script_and_fold(&bytes);
        let expected_rows = if keep_exited {
            format!(":12;[{}] 1\n:12;[new-x86-64] 1\n", fixture.file_name())
        } else {
            format!(":12;[{}] 2\n:13;[new-x86-64] 1\n", fixture.file_name())
        };
        assert_eq!(expected, expected_rows, "{script}");
        assert_eq!(
            fold_perfdata_callchains(&bytes).unwrap(),
            expected,
            "{script}"
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        assert_eq!(
            fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
            expected
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn reused_tid_does_not_keep_exited_threads_comm_like_native_perf() {
    let mut comm = comm_payload(11, 12, "stale");
    comm.resize(comm.len().next_multiple_of(8), 0);
    let mut bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm),
            record_bytes_with_misc(
                9,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample_payload(0x4000, 11, 12, [0x4000]),
            ),
            record_bytes(4, &fork_payload(11, 11, 12, 11, 0)),
            record_bytes(PERF_RECORD_FORK, &fork_payload(11, 11, 12, 11, 0)),
            record_bytes_with_misc(
                9,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample_payload(0x4000, 11, 12, [0x4000]),
            ),
        ],
    );
    put_u64(&mut bytes, 16, 144);
    let (script, expected) = native_script_and_fold(&bytes);
    assert_eq!(expected, ":12;[unknown] 1\nstale;[unknown] 1\n", "{script}");
    assert_eq!(
        fold_perfdata_callchains(&bytes).unwrap(),
        expected,
        "{script}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn fork_promotes_unknown_parent_pid_without_losing_its_comm_like_native_perf() {
    let mut comm = comm_payload(u32::MAX, 12, "parent");
    comm.resize(comm.len().next_multiple_of(8), 0);
    let mut bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm),
            record_bytes(PERF_RECORD_FORK, &fork_payload(22, 11, 22, 12, 0)),
            record_bytes_with_misc(
                9,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample_payload(0x4000, 22, 22, [0x4000]),
            ),
        ],
    );
    put_u64(&mut bytes, 16, 144);
    let (script, expected) = native_script_and_fold(&bytes);
    assert_eq!(expected, "parent;[unknown] 1\n", "{script}");
    assert_eq!(
        fold_perfdata_callchains(&bytes).unwrap(),
        expected,
        "{script}"
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    assert_eq!(
        fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
        expected
    );
}

#[cfg(target_os = "linux")]
#[test]
fn initial_module_failure_does_not_reserve_unwind_attachment_like_native_perf() {
    let fixture = SyntheticX86_64Object::create();
    for missing_mapping in [false, true] {
        let mmap = |path: &str| {
            let mut payload = mmap_payload(11, 11, 0, 0x10000, 0, path);
            payload.resize(payload.len().next_multiple_of(8), 0);
            record_bytes(1, &payload)
        };
        let sample = |tid| {
            record_bytes_with_misc(
                9,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    tid,
                    [],
                    1,
                    [0, 0x7fff_0000, 0x4000],
                    [0; 24],
                ),
            )
        };
        let mut records = Vec::new();
        if !missing_mapping {
            records.push(mmap(
                fixture.path.with_file_name("missing-elf").to_str().unwrap(),
            ));
        }
        records.extend([
            sample(12),
            mmap(&fixture.path_string()),
            sample(13),
            sample(12),
        ]);
        let mut bytes = perfdata_with_records_and_attrs_vec(
            vec![file_attr_bytes_with_regs(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_CALLCHAIN
                    | PERF_SAMPLE_REGS_USER
                    | PERF_SAMPLE_STACK_USER,
                (1 << 6) | (1 << 7) | (1 << 8),
            )],
            records,
        );
        put_u64(&mut bytes, 16, 144);
        let (script, expected) = native_script_and_fold(&bytes);
        assert_eq!(
            expected,
            format!(":13;[{}] 1\n", fixture.file_name()),
            "{script}"
        );
        assert_eq!(
            fold_perfdata_callchains(&bytes).unwrap(),
            expected,
            "{script}"
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        assert_eq!(
            fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
            expected
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn keeps_unwind_frame_for_valid_elf_named_perf_data_like_perf_libdw_and_inferno() {
    let fixture = SyntheticX86_64Object::create();
    let object_path = fixture.path.with_file_name("perf.data");
    std::fs::copy(&fixture.path, &object_path).expect("copy fixture ELF as perf.data");
    let object_path = object_path.to_str().expect("utf8 object path");
    let mut bytes = x86_leaf_only_perfdata(
        object_path,
        [0x7ffe_ff00, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
    );
    put_u64(&mut bytes, 16, 144);
    let perfdata = fixture.path.with_file_name("recording.perf.data");
    std::fs::write(&perfdata, bytes).expect("write recording");

    let perf = Command::new("perf")
        .args([
            "script",
            "--force",
            "-i",
            perfdata.to_str().expect("utf8 perfdata path"),
        ])
        .output()
        .expect("run perf script");
    assert!(
        perf.status.success(),
        "perf script failed: {}",
        String::from_utf8_lossy(&perf.stderr)
    );

    let mut inferno = Command::new("inferno-collapse-perf")
        .arg("-q")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run Inferno");
    inferno
        .stdin
        .take()
        .expect("Inferno stdin")
        .write_all(&perf.stdout)
        .expect("send perf script output to Inferno");
    let inferno = inferno.wait_with_output().expect("wait for Inferno");
    assert!(inferno.status.success());

    let folded = fold_perfdata_callchains(&std::fs::read(&perfdata).expect("read recording"))
        .expect("fold recording");
    assert_eq!(
        folded,
        String::from_utf8(inferno.stdout).expect("Inferno UTF-8 output")
    );
    assert_eq!(folded, ":12;[perf.data] 1\n");
}

#[test]
fn keeps_rbp_caller_after_first_non_text_mapping_like_perf_libdw() {
    // The register IP selects the second mapping when perf reports the DSO.
    // No FDE covers it; libdw retains the unmapped caller read from [RBP+8].
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x1000_0000, 0x1000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x1000_1000, 0x1000, 0x1000, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x1000_1000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[unknown];[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

#[test]
fn keeps_rbp_caller_from_executable_mmap2_like_perf_libdw() {
    // The executable mapping selects the DSO, but its FDE does not cover IP.
    // libdw's RBP fallback retains caller 0x1233 outside the recorded maps.
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x1000_0000, 0x0040_0000, 0, 1, current_exe.as_ref()),
            ),
            record_bytes(
                10,
                &mmap2_payload(
                    11,
                    11,
                    0x1000_2000,
                    0x0020_0000,
                    0x1000,
                    5,
                    current_exe.as_ref(),
                ),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x1000_5000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x1000_5000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[unknown];[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

#[cfg(target_os = "linux")]
#[test]
fn non_executable_user_mmap2_is_reported_to_unwinder_like_native_perf_libdw() {
    // perf util/unwind-libdw.c:__report_module reports the covering user DSO
    // without checking PROT_EXEC. The ELF's absent FDE uses the RBP fallback.
    let fixture = SyntheticX86_64Object::create();
    for prot in [0, 1, 3] {
        let mut mmap = mmap2_payload(11, 11, 0, 0x10000, 0, prot, &fixture.path_string());
        mmap.resize(mmap.len().next_multiple_of(8), 0);
        let bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes_with_regs(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_CALLCHAIN
                    | PERF_SAMPLE_REGS_USER
                    | PERF_SAMPLE_STACK_USER,
                (1 << 6) | (1 << 7) | (1 << 8),
            )],
            [
                record_bytes(10, &mmap),
                record_bytes_with_misc(
                    9,
                    PERF_RECORD_MISC_CPUMODE_USER,
                    &sample_payload_with_user_stack(
                        0x4000,
                        11,
                        11,
                        [],
                        1,
                        [0x7fff_0008, 0x7fff_0000, 0x4000],
                        [
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x34, 0x12, 0, 0, 0, 0,
                            0, 0,
                        ],
                    ),
                ),
            ],
        );
        let (script, expected) = native_script_and_fold(&bytes);
        assert_eq!(
            expected,
            format!(":11;[{0}];[{0}] 1\n", fixture.file_name()),
            "prot={prot}: {script}"
        );
        assert_eq!(
            fold_perfdata_callchains(&bytes).unwrap(),
            expected,
            "{script}"
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        assert_eq!(
            fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
            expected
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn read_only_caller_mapping_is_reported_to_unwinder_like_native_perf_libdw() {
    // unwind-libdw.c reports start-pgoff for both mappings. Reaching the
    // read-only prefix adds an overlapping whole-ELF module at another base.
    // This two-module layout retains both callers on all three samples.
    let fixture = SyntheticX86_64Object::create();
    let mmap = |start, len, pgoff, prot| {
        let mut payload = mmap2_payload(11, 11, start, len, pgoff, prot, &fixture.path_string());
        payload.resize(payload.len().next_multiple_of(8), 0);
        record_bytes(10, &payload)
    };
    let sample = || {
        record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_user_stack(
                0x1000_5000,
                11,
                11,
                [],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x1000_5000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0x10, 0, 0, 0, 0,
                ],
            ),
        )
    };
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            mmap(0x1000_0000, 0x1000, 0, 1),
            mmap(0x1000_2000, 0x10000, 0x1000, 5),
            sample(),
            sample(),
            sample(),
        ],
    );
    let (script, expected) = native_script_and_fold(&bytes);
    assert_eq!(
        expected,
        format!(":11;[{0}];[{0}] 3\n", fixture.file_name()),
        "{script}"
    );
    assert_eq!(
        fold_perfdata_callchains(&bytes).unwrap(),
        expected,
        "{script}"
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    assert_eq!(
        fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
        expected
    );
}

#[test]
fn keeps_rbp_caller_from_pid_specific_modules_like_perf_libdw() {
    // Only the sampled PID's mapping supplies the module for the initial IP.
    // Its missing-FDE RBP fallback also retains the unmapped caller 0x1233.
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x1000_0000, 0x30_0000, 0, 5, current_exe.as_ref()),
            ),
            record_bytes(
                10,
                &mmap2_payload(12, 12, 0x1000_1000, 0x30_0000, 0, 5, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x1000_5000,
                    12,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x1000_5000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[unknown];[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

/// Build a `--call-graph dwarf` `x86_64` perf.data with a single sample over the
/// synthetic fixture: one MMAP covering `[0, 0x1000_0000)` and one user-stack
/// sample. `regs` are `[bp, sp, ip]` in perf's ascending register order
/// (RBP=6, RSP=7, IP=8).
fn x86_leaf_only_perfdata(fixture_path: &str, regs: [u64; 3], stack: [u8; 24]) -> Vec<u8> {
    let mut mmap = mmap_payload(11, 11, 0, 0x1000_0000, 0, fixture_path);
    while !(8 + mmap.len()).is_multiple_of(8) {
        mmap.push(0);
    }
    perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap),
            record_bytes(
                9,
                &sample_payload_with_user_stack(regs[2], 11, 12, [], 1, regs, stack),
            ),
        ],
    )
}

#[test]
fn emits_scenario_d_leaf_when_no_cfi_and_bp_below_sp_like_perf_libdw() {
    // gap-5gr scenario D: the sampled IP (0x4000) is reported into a module
    // but no .eh_frame FDE covers it (the fixture's only FDE is at [0x100,
    // 0x104)), and bp < sp so elfutils' x86_64 rbp fallback (`if (sp >= fp)
    // return false;`, backends/x86_64_unwind.c) can never advance. libdwfl
    // fires the initial-frame callback exactly once, so perf prints the single
    // leaf. bp=0x7ffe_ff00 < sp=0x7fff_0000.
    let fixture = SyntheticX86_64Object::create();
    let bytes = x86_leaf_only_perfdata(
        &fixture.path_string(),
        [0x7ffe_ff00, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    assert_eq!(folded, format!(":12;[{}] 1\n", fixture.file_name()));
}

#[test]
fn unwinds_rbp_caller_when_bp_at_or_above_sp_and_no_cfi_like_perf_libdw() {
    // With no covering FDE, elfutils falls back to [RBP+8], not [SP].
    // The return slot is 0x1234, so perf emits adjusted caller 0x1233.
    // The broad mapping gives both frames the same DSO fallback label.
    let fixture = SyntheticX86_64Object::create();
    let bytes = x86_leaf_only_perfdata(
        &fixture.path_string(),
        [0x7fff_0008, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    assert_eq!(folded, format!(":12;[{0}];[{0}] 1\n", fixture.file_name()));
}

#[test]
fn nops_only_cfi_recovers_same_rip_with_perf_libdw_abi_defaults() {
    // elfutils backends/x86_64_cfi.c:x86_64_abi_cfi initializes register 16
    // (RIP) to DW_CFA_same_value. This covering FDE has only nops, so it
    // recovers the sampled RIP despite having no explicit register rules.
    // libdwfl/dwfl_frame_pc.c:dwfl_frame_pc marks this caller non-activation;
    // perf util/unwind-libdw.c:frame_callback subtracts one, yielding 0xff.
    // That address has no covering FDE and BP < SP stops the RBP fallback.
    let fixture = SyntheticX86_64Object::create();
    let bytes = x86_leaf_only_perfdata(
        &fixture.path_string(),
        [0x7ffe_ff00, 0x7fff_0000, 0x100],
        [0_u8; 24],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    assert_eq!(folded, format!(":12;[{0}];[{0}] 1\n", fixture.file_name()));
}

#[test]
fn skip_gate_is_byte_identical_to_running_the_full_unwind_for_leaf_only_samples() {
    // The gap-pkh skip gate is a pure optimization: classifying a leaf-only
    // sample and skipping framehop must produce the exact same folded output
    // as running framehop and letting the shared acceptance tail truncate to
    // the leaf. The fold path always takes the gated route, so we assert the
    // gated output equals the independently-known perf-correct single leaf.
    let fixture = SyntheticX86_64Object::create();
    let leaf_only = x86_leaf_only_perfdata(
        &fixture.path_string(),
        [0x7ffe_ff00, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
    );

    let gated = fold_perfdata_callchains(&leaf_only).expect("folded");
    assert_eq!(gated, format!(":12;[{}] 1\n", fixture.file_name()));
}

#[test]
fn emits_scenario_d_leaf_on_aarch64_when_no_cfi_and_lr_is_zero_like_perf_libdw() {
    // gap-5gr scenario D on aarch64: pc (0x4000) is reported into a module with
    // no FDE covering it (the fixture's only FDE is [0x100, 0x104)) and lr == 0,
    // so elfutils' backends/aarch64_unwind.c fails before producing any caller
    // (`if (lr == 0 || !setfunc(...)) return false;`). libdwfl fires the
    // initial-frame callback exactly once, so perf prints the single leaf.
    // Registers are ascending fp(29), lr(30), sp(31), pc(32) = [fp, lr, sp, pc].
    let fixture = SyntheticAarch64Object::create();
    let mask = (1_u64 << 29) | (1_u64 << 30) | (1_u64 << 31) | (1_u64 << 32);
    let bytes = perfdata_with_records_attrs_and_arch_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            mask,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0, 0x1000_0000, 0, fixture.path_string().as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    // fp = 0x1010, lr = 0 (ends the walk), sp = 0x1000, pc = 0x4000.
                    [0x1010, 0, 0x1000, 0x4000],
                    [0_u8; 0x40],
                ),
            ),
        ],
        "aarch64",
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    assert_eq!(folded, format!(":12;[{}] 1\n", fixture.file_name()));
}

#[cfg(target_os = "linux")]
#[test]
fn keeps_object_unwind_dso_leaf_when_framehop_only_returns_current_ip_like_perf_libdw() {
    let Some(libc) = process_libc_path() else {
        return;
    };
    let libc_bytes = std::fs::read(&libc).expect("read libc");
    let object = object::File::parse(&libc_bytes[..]).expect("parse libc");
    let Some(symbol) = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("__memcmp_avx2_movbe"))
    else {
        return;
    };
    let Some(segment) = object.segments().find(|segment| {
        let start = segment.address();
        let end = start.saturating_add(segment.size());
        start <= symbol.address() && symbol.address() < end
    }) else {
        return;
    };
    let base = 0x7000_0000_0000_u64;
    let pgoff = segment.file_range().0;
    let start = base + pgoff;
    let ip_offset = symbol.address() + 0xe0;
    let ip = base + ip_offset;
    let libc = libc.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(
                    11,
                    11,
                    start,
                    segment.file_range().1,
                    pgoff,
                    5,
                    libc.as_ref(),
                ),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    ip,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, ip],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = ":12;[libc.so.6] 1\n".to_string();

    assert_eq!(folded, expected);
}

#[test]
fn drops_dwarf_user_stack_when_only_synthetic_mappings_exist_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_frames_from_anon_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1200, 0x100, 0, "[anon]")),
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_frames_from_slash_anon_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1200, 0x100, 0, "//anon")),
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn symbolized_fold_drops_dwarf_user_stack_when_object_cannot_be_loaded_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_when_late_synthetic_mapping_cannot_be_loaded_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        1, 0x80, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
            record_bytes(1, &mmap_payload(11, 11, 0x8000, 0x100, 0, "/tmp/lib")),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn skips_object_unwind_when_sampled_ip_has_no_mapping_before_mmap2_frame() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x1200, 0x100, 0, 1, "/tmp/perf.data"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn skips_unwind_when_sampled_ip_is_outside_mapped_library_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x1200, 0x100, 0, 1, "/lib/libc.so.6"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn skips_unwind_when_sampled_ip_is_outside_stack_mapping_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(10, &mmap2_payload(11, 11, 0x1200, 0x100, 0, 1, "[stack]")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn skips_object_unwind_when_sampled_ip_has_no_mapping_before_mmap_frame() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1200, 0x100, 0, "/tmp/perf.data")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[cfg(target_os = "linux")]
#[test]
fn mapping_arriving_after_sample_is_not_applied_retroactively_like_perf_script() {
    let mut mmap = mmap_payload(11, 11, 0x1200, 0x100, 0, "/tmp/perf.data");
    while !(8 + mmap.len()).is_multiple_of(8) {
        mmap.push(0);
    }
    let mut bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
            record_bytes(1, &mmap),
        ],
    );
    put_u64(&mut bytes, 16, 144);

    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("recording.perf.data");
    std::fs::write(&perfdata, &bytes).expect("write recording");
    let perf = Command::new("perf")
        .args([
            "script",
            "--force",
            "-i",
            perfdata.to_str().expect("utf8 perfdata path"),
        ])
        .output()
        .expect("run perf script");
    assert!(
        perf.status.success(),
        "perf script failed: {}",
        String::from_utf8_lossy(&perf.stderr)
    );

    let mut inferno = Command::new("inferno-collapse-perf")
        .arg("-q")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run Inferno");
    inferno
        .stdin
        .take()
        .expect("Inferno stdin")
        .write_all(&perf.stdout)
        .expect("send perf script output to Inferno");
    let inferno = inferno.wait_with_output().expect("wait for Inferno");
    assert!(inferno.status.success());

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    assert_eq!(
        folded,
        String::from_utf8(inferno.stdout).expect("Inferno UTF-8 output"),
        "perf script:\n{}",
        String::from_utf8_lossy(&perf.stdout)
    );
}

#[test]
fn folds_callchains_in_flamegraph_root_to_leaf_order() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0x2000, 0x3000, 0x4000]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn includes_record_context_when_sample_parsing_fails() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(9, &[0; 8])],
    );

    let error = summarize_perfdata(&bytes).expect_err("bad sample");

    assert!(error.contains("record type 9"));
    assert!(error.contains("offset"));
}

#[test]
fn folds_identical_sample_callchains_as_hex_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000, 0x3000])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000, 0x3000])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n:12;[unknown];[unknown] 2\n");
}

#[test]
fn drops_perf_context_marker_frames_when_folding() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0xffff_ffff_ffff_fe00, 0x2000]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn disabled_deferral_retains_cookie_without_tid_sample_id_like_perf_script() {
    // evsel.c:3391 requires attr.defer_callchain before treating the final
    // address as a cookie. This fixture leaves bit38 disabled.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0x2000, 0x3000, 0xffff_ffff_ffff_fd80, 0x4444],
                ),
            ),
            record_bytes(22, &callchain_deferred_payload(0x4444, [0x5000, 0x6000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn disabled_deferral_does_not_merge_even_with_matching_tid_sample_id_like_perf_script() {
    // evsel.c:3391 and session.c:1486 require attr.defer_callchain; a matching
    // TID/cookie cannot merge a sample that was never queued for deferral.
    let mut deferred = callchain_deferred_payload(0x4444, [0x5000, 0x6000]);
    deferred.extend(11_u32.to_le_bytes());
    deferred.extend(12_u32.to_le_bytes());
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0x2000, 0x3000, 0xffff_ffff_ffff_fd80, 0x4444],
                ),
            ),
            record_bytes(22, &deferred),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn disabled_deferral_retains_cookie_when_a_different_tid_record_arrives_like_perf_script() {
    // evsel.c:3391 requires bit38. No deferral occurs in this fixture, so the
    // original cookie is an address regardless of the later record's TID.
    let mut deferred = callchain_deferred_payload(0x4444, [0x5000, 0x6000]);
    deferred.extend(11_u32.to_le_bytes());
    deferred.extend(99_u32.to_le_bytes());
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0x2000, 0x3000, 0xffff_ffff_ffff_fd80, 0x4444],
                ),
            ),
            record_bytes(22, &deferred),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn disabled_deferral_retains_cookie_when_a_different_cookie_record_arrives_like_perf_script() {
    // evsel.c:3391 requires bit38. Without it, the cookie is a normal frame
    // and the sample is delivered without waiting for a matching record.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0x2000, 0x3000, 0xffff_ffff_ffff_fd80, 0x4444],
                ),
            ),
            record_bytes(22, &callchain_deferred_payload(0x5555, [0x5000, 0x6000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn omits_samples_that_have_no_frames_after_filtering_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0xffff_ffff_ffff_fe00]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn missing_sample_thread_comm_uses_perf_thread_placeholder() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "sftp-s3")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn prefixes_folded_stacks_with_sample_tid_comm_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                3,
                &comm_payload_with_sample_id_time(11, 12, "perf-exec", 10),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 11, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "pyroclast;[unknown] 1\n");
}

#[test]
fn uses_comm_name_from_sample_time_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "perf-exec")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x3000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 2\n");
}

#[test]
fn thread_comm_takes_precedence_over_process_exec_comm_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                3,
                &comm_payload_with_sample_id_time(11, 12, "perf-exec", 10),
            ),
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload(11, 11, "pyroclast"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "perf-exec;[unknown] 1\n");
}

#[test]
fn process_exec_comm_is_fallback_when_sample_thread_has_no_comm() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload(11, 11, "pyroclast"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn resolves_each_sample_before_later_remaps_like_perf_script() {
    // perf util/session.c perf_session__deliver_event() invokes
    // builtin-script.c process_sample_event()/machine__resolve() before the
    // next ordered mmap is applied. Inferno counts the emitted label, not IPs.
    let mapping = |path: &str, time: u64| {
        let mut payload = mmap_payload(11, 12, 0x1000, 0x1000, 0, path);
        payload.extend(11_u32.to_le_bytes());
        payload.extend(12_u32.to_le_bytes());
        payload.extend(time.to_le_bytes());
        record_bytes(1, &payload)
    };
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            mapping("/missing/first.so", 10),
            record_bytes(9, &sample_payload_with_time(0x1010, 11, 12, 20, [0x1010])),
            mapping("/missing/second.so", 30),
            record_bytes(9, &sample_payload_with_time(0x1010, 11, 12, 40, [0x1010])),
        ],
    );
    let expected = ":12;[first.so] 1\n:12;[second.so] 1\n";
    assert_eq!(fold_perfdata_callchains(&bytes).unwrap(), expected);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    assert_eq!(
        fold_perfdata_file_with_options(file.path(), FoldOptions::default()).unwrap(),
        expected
    );
}

#[test]
fn applies_comm_records_by_perf_timestamp_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            record_bytes(
                3,
                &comm_payload_with_sample_id_time(11, 12, "perf-exec", 10),
            ),
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload_with_sample_id_time(11, 11, "pyroclast", 20),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "perf-exec;[unknown] 1\n");
}

#[test]
fn normalizes_comm_spaces_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 12, "V8 WorkerThread")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "V8_WorkerThread;[unknown] 1\n");
}

#[test]
fn untimed_samples_use_infernos_unit_weight_even_with_period_fields() {
    // perf builtin-script.c:evsel__do_check_stype removes absent TIME.
    // Inferno perf.rs:on_event_line parses after the first colon; without
    // TIME it cannot recover the preceding period and after_event uses 1.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 3, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 2\n");
}

#[cfg(target_os = "linux")]
#[test]
fn period_weights_with_and_without_timestamps_match_real_perf_script_and_inferno() {
    use inferno::collapse::Collapse as _;

    // builtin-script.c:evsel__check_attr checks TIME with
    // evsel__do_check_stype, removing absent default fields. Compare the
    // resulting native headers, not just our own script writer's grammar.
    for timed in [false, true] {
        for callchain in [false, true] {
            let mut sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD;
            if timed {
                sample_type |= PERF_SAMPLE_TIME;
            }
            if callchain {
                sample_type |= PERF_SAMPLE_CALLCHAIN;
            }
            let mut comm = comm_payload(11, 12, "worker");
            comm.resize(comm.len().next_multiple_of(8), 0);
            let mut records = vec![record_bytes(3, &comm)];
            for period in [7, 3] {
                let mut payload = if callchain {
                    sample_payload_with_period(0x2000, 11, 12, period, [0x2000])
                } else {
                    sample_payload_with_period_no_callchain(0x2000, 11, 12, period)
                };
                if timed {
                    payload.splice(16..16, 1_000_000_000_u64.to_le_bytes());
                }
                records.push(record_bytes_with_misc(
                    PERF_RECORD_SAMPLE,
                    PERF_RECORD_MISC_CPUMODE_USER,
                    &payload,
                ));
            }
            let mut bytes = perfdata_with_records_and_attrs_vec(
                vec![file_attr_bytes(sample_type, 0, 0)],
                records,
            );
            put_u64(&mut bytes, 16, 144);
            let root = tempfile::tempdir().expect("tempdir");
            let input = root.path().join("perf.data");
            std::fs::write(&input, &bytes).expect("write fixture");
            let perf = Command::new("perf")
                .args(["script", "--force", "-i"])
                .arg(&input)
                .output()
                .expect("run perf script");
            assert!(
                perf.status.success(),
                "{}",
                String::from_utf8_lossy(&perf.stderr)
            );
            let mut native = Vec::new();
            inferno::collapse::perf::Folder::default()
                .collapse(std::io::Cursor::new(&perf.stdout), &mut native)
                .expect("native Inferno");
            let folded = fold_perfdata_callchains_with_options(
                &bytes,
                FoldOptions {
                    count_periods: true,
                    inline: false,
                },
            )
            .expect("fold fixture");
            assert_eq!(
                folded.as_bytes(),
                native,
                "timed={timed}, callchain={callchain}, native script={}",
                String::from_utf8_lossy(&perf.stdout)
            );
            if timed || callchain {
                assert_eq!(
                    folded,
                    format!("worker;[unknown] {}\n", if timed { 10 } else { 2 })
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn native_script_and_fold(bytes: &[u8]) -> (String, String) {
    use inferno::collapse::Collapse as _;
    let mut bytes = bytes.to_vec();
    put_u64(&mut bytes, 16, 144);
    let root = tempfile::tempdir().expect("tempdir");
    let input = root.path().join("perf.data");
    std::fs::write(&input, bytes).expect("write fixture");
    let perf = Command::new("perf")
        .args(["script", "--force", "-i"])
        .arg(&input)
        .output()
        .expect("perf script");
    assert!(
        perf.status.success(),
        "{}",
        String::from_utf8_lossy(&perf.stderr)
    );
    let mut folded = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(std::io::Cursor::new(&perf.stdout), &mut folded)
        .expect("native Inferno");
    (
        String::from_utf8(perf.stdout).expect("native script"),
        String::from_utf8(folded).expect("native fold"),
    )
}

#[cfg(target_os = "linux")]
fn assert_native_module_kallsyms_parity(
    kallsyms: &str,
    sampled_ip: u64,
    expected_native_frame: &str,
    expected_ends: &[(&str, u64)],
) {
    let mut expected_rows = [
        "worker;_stext 1\n".to_string(),
        format!("worker;{expected_native_frame} 1\n"),
    ];
    expected_rows.sort();
    assert_native_module_kallsyms_queries_parity(
        kallsyms,
        &[sampled_ip],
        Some(&expected_rows.concat()),
        expected_ends,
    );
}

#[cfg(target_os = "linux")]
fn write_native_module_kallsyms_fixture(
    kallsyms: &str,
    sampled_ips: &[u64],
    distinct_queries: bool,
    module_paths: [&str; 2],
) -> (tempfile::TempDir, Vec<u8>) {
    // Kernel-first fixtures initialize ordinary kallsyms before module queries.
    let ordered = std::iter::once(0xffff_ffff_8100_0010)
        .chain(sampled_ips.iter().copied())
        .collect::<Vec<_>>();
    write_native_ordered_module_kallsyms_fixture(kallsyms, &ordered, distinct_queries, module_paths)
}

#[cfg(target_os = "linux")]
fn write_native_ordered_module_kallsyms_fixture(
    kallsyms: &str,
    sampled_ips: &[u64],
    distinct_queries: bool,
    module_paths: [&str; 2],
) -> (tempfile::TempDir, Vec<u8>) {
    let queries = sampled_ips.iter().map(|&ip| (ip, ip)).collect::<Vec<_>>();
    write_native_module_sample_and_chain_fixture(kallsyms, &queries, distinct_queries, module_paths)
}

#[cfg(target_os = "linux")]
fn write_native_module_sample_and_chain_fixture(
    kallsyms: &str,
    queries: &[(u64, u64)],
    distinct_queries: bool,
    module_paths: [&str; 2],
) -> (tempfile::TempDir, Vec<u8>) {
    const KERNEL_START: u64 = 0xffff_ffff_8100_0000;
    const MODULE_START: u64 = 0xffff_ffff_c100_0000;

    let fixture_parent =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/native-kallsyms-fixtures");
    std::fs::create_dir_all(&fixture_parent).expect("fixture parent");
    let root = tempfile::Builder::new()
        .prefix("module-symbols-")
        .tempdir_in(&fixture_parent)
        .expect("fixture directory");
    let symfs = root.path().join("symfs");
    std::fs::create_dir(&symfs).expect("empty symfs");
    let kallsyms_path = root.path().join("kallsyms");
    std::fs::write(&kallsyms_path, kallsyms).expect("synthetic kallsyms");

    let mut comm = comm_payload(11, 12, "worker");
    comm.resize(comm.len().next_multiple_of(8), 0);
    let mut records = vec![record_bytes(3, &comm)];
    // machine.c:machine__process_kernel_mmap_event creates module maps by
    // name. The broad initial kernel map also contains the synthetic core
    // boundary; symbol.c:maps__split_kallsyms therefore keeps it in that DSO.
    for (start, len, pgoff, path) in [
        (
            KERNEL_START,
            MODULE_START + 0x4000 - KERNEL_START,
            KERNEL_START,
            "[kernel.kallsyms]_stext",
        ),
        (MODULE_START, 0x4000, 0, module_paths[0]),
        (MODULE_START + 0x1_0000, 0x4000, 0, module_paths[1]),
    ] {
        let mut payload = mmap_payload(u32::MAX, u32::MAX, start, len, pgoff, path);
        payload.resize(payload.len().next_multiple_of(8), 0);
        records.push(record_bytes_with_misc(
            1,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &payload,
        ));
    }
    for (index, (sample_ip, chain_ip)) in queries.iter().copied().enumerate() {
        if distinct_queries {
            // Distinct comms keep each query separate in the folded oracle,
            // so swapped lookup results cannot cancel in aggregate counts.
            let mut payload = comm_payload(11, 12, &format!("query_{index:02}"));
            payload.resize(payload.len().next_multiple_of(8), 0);
            records.push(record_bytes(3, &payload));
        }
        records.push(record_bytes_with_misc(
            PERF_RECORD_SAMPLE,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_time(
                sample_ip,
                11,
                12,
                1_000_000_000 + u64::try_from(index).expect("sample index"),
                [0xffff_ffff_ffff_ff80, chain_ip],
            ),
        ));
    }
    let mut attr = file_attr_bytes(
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
        0,
        0,
    );
    // evsel.c:3232 uses attr.sample_period when PERF_SAMPLE_PERIOD is absent.
    put_u64(&mut attr, 16, 1);
    let mut bytes = perfdata_with_records_and_attrs_vec(vec![attr], records);
    put_u64(&mut bytes, 16, 144);
    let input = root.path().join("perf.data");
    std::fs::write(&input, &bytes).expect("synthetic perf.data");
    (root, bytes)
}

#[cfg(target_os = "linux")]
fn query_native_module_kallsyms(
    root: &std::path::Path,
    expected_ends: &[(&str, u64)],
) -> (String, String, Vec<u8>) {
    use inferno::collapse::Collapse as _;

    let perf = Command::new("perf")
        .args(["script", "--force", "-vvvv", "--kallsyms"])
        .arg(root.join("kallsyms"))
        .arg("--symfs")
        .arg(root.join("symfs"))
        .arg("-i")
        .arg(root.join("perf.data"))
        .output()
        .expect("native perf kallsyms oracle");
    let stderr = String::from_utf8_lossy(&perf.stderr);
    assert!(perf.status.success(), "native perf failed: {stderr}");
    let script = String::from_utf8(perf.stdout).expect("native script UTF-8");
    // util/symbol.c:symbols__fixup_end, lines 276-298, logs each nonterminal
    // extent before duplicate removal. Include the module suffix so aliases
    // in different DSOs cannot accidentally satisfy the same assertion.
    for &(name, end) in expected_ends {
        let expected = format!("symbols__fixup_end sym:{name} end:{end:#x}");
        assert!(
            stderr.lines().any(|line| line.ends_with(&expected)),
            "missing native extent {expected:?}\nscript={script}\nstderr={stderr}"
        );
    }
    let mut native = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(std::io::Cursor::new(script.as_bytes()), &mut native)
        .expect("collapse native script");
    (script, stderr.into_owned(), native)
}

#[cfg(target_os = "linux")]
fn assert_module_symbol_routes_match_native(
    root: &std::path::Path,
    bytes: &[u8],
    script: &str,
    native: &[u8],
) {
    use pyroclast::symbols::{SelectedObjectResolver, SymbolizerKind};
    let runner = pyroclast::process::RealCommandRunner::default();
    let input = root.join("perf.data");
    for symbolizer in [SymbolizerKind::RustAddr2line, SymbolizerKind::Addr2line] {
        for inline in [false, true] {
            for file_route in [false, true] {
                let resolver =
                    perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                        SelectedObjectResolver::new(&runner, symbolizer),
                        &input,
                        root,
                        [],
                        &root.join("kallsyms"),
                    );
                let options = FoldOptions {
                    inline,
                    count_periods: true,
                };
                let actual = if file_route {
                    pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                        &input, options, &resolver,
                    )
                } else {
                    fold_perfdata_callchains_with_symbols(bytes, options, &resolver)
                }
                .unwrap();
                assert_eq!(
                    actual.as_bytes(),
                    native,
                    "{symbolizer:?}, inline={inline}, file={file_route}: {script}"
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn assert_native_module_kallsyms_queries_parity(
    kallsyms: &str,
    sampled_ips: &[u64],
    expected_native: Option<&str>,
    expected_ends: &[(&str, u64)],
) {
    let (root, bytes) = write_native_module_kallsyms_fixture(
        kallsyms,
        sampled_ips,
        expected_native.is_none(),
        ["[a]", "[b]"],
    );
    let (script, stderr, native) = query_native_module_kallsyms(root.path(), expected_ends);
    // Establish the native result independently before checking Pyroclast.
    if let Some(expected) = expected_native {
        assert_eq!(
            native,
            expected.as_bytes(),
            "native fixture did not exercise the intended case\nscript={script}\nstderr={stderr}"
        );
    } else {
        let native_text = std::str::from_utf8(&native).expect("native folded UTF-8");
        let allowed_frames = kallsyms
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                fields.next()?;
                fields.next()?;
                let name = fields.next()?;
                (fields.next() == Some("[a]")).then_some(name)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            native_text.lines().count(),
            sampled_ips.len() + 1,
            "native query loss\nscript={script}"
        );
        assert!(native_text.lines().any(|line| line == "query_00;_stext 1"));
        for index in 1..=sampled_ips.len() {
            let prefix = format!("query_{index:02};");
            let frame = native_text
                .lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .and_then(|line| line.strip_suffix(" 1"))
                .expect("native unit-weight query row");
            assert!(
                frame == "[[a]]" || allowed_frames.contains(&frame),
                "native query {index} escaped the module fixture: {frame}\nscript={script}"
            );
        }
    }

    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        StaticSymbolResolver,
        &root.path().join("perf.data"),
        root.path(),
        [],
        &root.path().join("kallsyms"),
    );
    let actual = fold_perfdata_callchains_with_symbols(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
        &resolver,
    )
    .expect("fold synthetic module kallsyms");
    assert_eq!(actual.as_bytes(), native, "native script={script}");
}

#[cfg(target_os = "linux")]
fn resolved_kernel_dso<'a>(
    resolver: &impl SymbolResolver,
    mapping: &pyroclast::perfdata::mappings::ResolvedMappingRef<'a>,
) -> &'a str {
    let request = SymbolRequest {
        kernel_module_address: None,
        path: mapping.path.into(),
        relative_address: mapping.relative_address,
        kernel_mapping_range: Some((mapping.start, mapping.end)),
        build_id: None,
        file_identity: None,
        kernel_relocation: mapping.kernel_relocation.clone(),
    };
    if resolver
        .resolve_frame_batch_with_metadata(&[request])
        .unwrap()[0]
        .kernel_dso
        == pyroclast::symbols::SymbolDsoName::KernelKallsyms
    {
        "[kernel.kallsyms]"
    } else {
        mapping.path
    }
}

#[cfg(target_os = "linux")]
fn write_native_kcore_fixture(module_path: &str) -> (tempfile::TempDir, Vec<u8>) {
    write_native_ordered_kcore_fixture(module_path, &[0xffff_ffff_8100_0010, 0xffff_ffff_c100_0010])
}

#[cfg(target_os = "linux")]
fn write_native_ordered_kcore_fixture(
    module_path: &str,
    sampled_ips: &[u64],
) -> (tempfile::TempDir, Vec<u8>) {
    let (root, bytes) = write_native_ordered_module_kallsyms_fixture(
        "ffffffff81000000 T _stext\n\
         ffffffff81000100 T _etext\n\
         ffffffffc1000000 T first\t[a]\n\
         ffffffffc1000200 T next\t[a]\n\
         ffffffffc1010000 T sentinel\t[b]\n",
        sampled_ips,
        false,
        [module_path, "[b]"],
    );
    std::fs::write(
        root.path().join("modules"),
        "a 16384 0 - Live 0xffffffffc1000000\nb 16384 0 - Live 0xffffffffc1010000\n",
    )
    .unwrap();
    // Only ELF/program headers are needed: these large kernel ranges carry no
    // copied kernel memory or executable payload.
    let mut elf = vec![0_u8; 64 + 2 * 56];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&4_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&2_u16.to_le_bytes());
    for (index, (start, len)) in [
        (0xffff_ffff_8100_0000_u64, 0x10000_u64),
        (0xffff_ffff_c100_0000, 0x20000),
    ]
    .into_iter()
    .enumerate()
    {
        let offset = 64 + index * 56;
        elf[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        elf[offset + 4..offset + 8].copy_from_slice(&7_u32.to_le_bytes());
        elf[offset + 8..offset + 16]
            .copy_from_slice(&(4096_u64 + u64::try_from(index).unwrap() * 0x1_0000).to_le_bytes());
        elf[offset + 16..offset + 24].copy_from_slice(&start.to_le_bytes());
        elf[offset + 32..offset + 40].copy_from_slice(&len.to_le_bytes());
        elf[offset + 40..offset + 48].copy_from_slice(&len.to_le_bytes());
    }
    std::fs::write(root.path().join("kcore"), elf).unwrap();
    (root, bytes)
}

#[cfg(target_os = "linux")]
#[test]
fn native_kcore_replaces_module_dso_names_only_when_recorded_addresses_match() {
    const MODULE_IP: u64 = 0xffff_ffff_c100_0010;
    let (root, bytes) = write_native_kcore_fixture("[a]");
    let (script, stderr, _) = query_native_module_kallsyms(root.path(), &[]);
    assert!(
        stderr.contains("Using ") && stderr.contains("/kcore for kernel data"),
        "{stderr}"
    );
    assert!(
        script.contains("first+0x10 ([kernel.kallsyms])"),
        "{script}"
    );
    let summary = summarize_perfdata(&bytes).unwrap();
    let mapping = summary.mmap_table.resolve_ref(11, MODULE_IP).unwrap();
    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        StaticSymbolResolver,
        &root.path().join("perf.data"),
        root.path(),
        [],
        &root.path().join("kallsyms"),
    );
    let core = summary
        .mmap_table
        .resolve_ref(11, 0xffff_ffff_8100_0010)
        .unwrap();
    assert_eq!(resolved_kernel_dso(&resolver, &core), "[kernel.kallsyms]");
    assert_eq!(
        resolved_kernel_dso(&resolver, &mapping),
        "[kernel.kallsyms]"
    );
    let request = SymbolRequest {
        kernel_module_address: None,
        path: "[a]".into(),
        relative_address: MODULE_IP,
        kernel_mapping_range: Some((mapping.start, mapping.end)),
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    assert_eq!(
        resolver
            .resolve_batch(std::slice::from_ref(&request))
            .unwrap(),
        [Some("first+0x10".into())]
    );
    for inline in [false, true] {
        let actual = fold_perfdata_callchains_with_symbols(
            &bytes,
            FoldOptions {
                inline,
                count_periods: true,
            },
            &resolver,
        )
        .unwrap();
        let (_, _, native) = query_native_module_kallsyms(root.path(), &[]);
        assert_eq!(actual.as_bytes(), native);
    }
    let new_resolver = || {
        perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            StaticSymbolResolver,
            &root.path().join("perf.data"),
            root.path(),
            [],
            &root.path().join("kallsyms"),
        )
    };
    // Matching kernel identity alone cannot validate a module loaded elsewhere.
    std::fs::write(
        root.path().join("modules"),
        "a 16384 0 - Live 0xffffffffc1001000\nb 16384 0 - Live 0xffffffffc1010000\n",
    )
    .unwrap();
    let (script, _, _) = query_native_module_kallsyms(root.path(), &[]);
    assert!(script.contains("first+0x10 ([a])"), "{script}");
    assert_eq!(resolved_kernel_dso(&new_resolver(), &mapping), "[a]");
    std::fs::write(
        root.path().join("modules"),
        "a 16384 0 - Live 0xffffffffc1000000\nb 16384 0 - Live 0xffffffffc1010000\n",
    )
    .unwrap();
    // A relocated core can use relocated kallsyms but cannot reuse live kcore.
    let mut relocated = bytes.clone();
    let name = b"[kernel.kallsyms]_stext";
    let offset = relocated
        .windows(name.len())
        .position(|bytes| bytes == name)
        .unwrap();
    put_u64(&mut relocated, offset - 8, 0xffff_ffff_8100_1000);
    std::fs::write(root.path().join("perf.data"), &relocated).unwrap();
    let (script, _, _) = query_native_module_kallsyms(root.path(), &[]);
    assert!(script.contains("first+0x10 ([a])"), "{script}");
    assert_eq!(resolved_kernel_dso(&new_resolver(), &mapping), "[a]");
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    std::fs::write(root.path().join("kcore"), b"truncated").unwrap();
    assert_eq!(resolved_kernel_dso(&new_resolver(), &mapping), "[a]");
}

#[cfg(target_os = "linux")]
#[test]
fn native_kcore_accepts_matching_absolute_and_compressed_module_addresses() {
    use pyroclast::symbols::{SelectedObjectResolver, SymbolizerKind};
    let runner = pyroclast::process::RealCommandRunner::default();
    for module_path in [
        "/lib/modules/a.ko",
        "/lib/modules/a.ko.gz",
        "/lib/modules/a.ko.xz",
    ] {
        let (root, bytes) = write_native_kcore_fixture(module_path);
        // The fixture loads core first. Native validates the module's canonical
        // short DSO name (symbol.c:do_validate_kcore_modules_cb, dso.c:__kmod_path__parse).
        let (script, stderr, native) = query_native_module_kallsyms(root.path(), &[]);
        assert!(
            stderr.contains("/kcore for kernel data"),
            "{module_path}: {stderr}"
        );
        assert!(
            script.contains("first+0x10 ([kernel.kallsyms])"),
            "{module_path}: {script}"
        );
        let input = root.path().join("perf.data");
        for (symbolizer, inline, file_route) in [
            (SymbolizerKind::RustAddr2line, false, false),
            (SymbolizerKind::RustAddr2line, false, true),
            (SymbolizerKind::RustAddr2line, true, false),
            (SymbolizerKind::RustAddr2line, true, true),
            (SymbolizerKind::Addr2line, false, false),
            (SymbolizerKind::Addr2line, false, true),
            (SymbolizerKind::Addr2line, true, false),
            (SymbolizerKind::Addr2line, true, true),
        ] {
            let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                SelectedObjectResolver::new(&runner, symbolizer),
                &input,
                root.path(),
                [],
                &root.path().join("kallsyms"),
            );
            let options = FoldOptions {
                inline,
                count_periods: true,
            };
            let actual = if file_route {
                pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                    &input, options, &resolver,
                )
            } else {
                fold_perfdata_callchains_with_symbols(&bytes, options, &resolver)
            }
            .unwrap();
            assert_eq!(
                actual.as_bytes(),
                native,
                "{module_path}, {symbolizer:?}, inline={inline}, file={file_route}: {script}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn absolute_module_kallsyms_fallback_matches_native_with_missing_or_rejected_kcore() {
    use pyroclast::symbols::{SelectedObjectResolver, SymbolizerKind};
    let runner = pyroclast::process::RealCommandRunner::default();
    for (module_path, missing) in [
        ("/lib/modules/a.ko", true),
        ("/lib/modules/a.ko.gz", true),
        ("/lib/modules/a.ko.xz", true),
        ("/lib/modules/a.ko", false),
        ("/lib/modules/a.ko.gz", false),
        ("/lib/modules/a.ko.xz", false),
    ] {
        let (root, bytes) = write_native_kcore_fixture(module_path);
        let kcore = root.path().join("kcore");
        if missing {
            std::fs::remove_file(kcore).unwrap();
        } else {
            std::fs::write(kcore, b"truncated").unwrap();
        }
        let (script, stderr, native) = query_native_module_kallsyms(root.path(), &[]);
        assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
        assert!(script.contains("first+0x10 ([a])"), "{script}\n{stderr}");
        let input = root.path().join("perf.data");
        for (symbolizer, inline, file_route) in [
            (SymbolizerKind::RustAddr2line, false, false),
            (SymbolizerKind::RustAddr2line, false, true),
            (SymbolizerKind::RustAddr2line, true, false),
            (SymbolizerKind::RustAddr2line, true, true),
            (SymbolizerKind::Addr2line, false, false),
            (SymbolizerKind::Addr2line, false, true),
            (SymbolizerKind::Addr2line, true, false),
            (SymbolizerKind::Addr2line, true, true),
        ] {
            let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                SelectedObjectResolver::new(&runner, symbolizer),
                &input,
                root.path(),
                [],
                &root.path().join("kallsyms"),
            );
            let options = FoldOptions {
                inline,
                count_periods: true,
            };
            let actual = if file_route {
                pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                    &input, options, &resolver,
                )
            } else {
                fold_perfdata_callchains_with_symbols(&bytes, options, &resolver)
            }
            .unwrap();
            assert_eq!(
                actual.as_bytes(),
                native,
                "{module_path}, missing={missing}, {symbolizer:?}, inline={inline}, file={file_route}: {script}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn absolute_kernel_module_elf_precedes_kallsyms_when_kcore_is_missing() {
    assert_native_module_object_queries(&[0xffff_ffff_8100_0010, 0xffff_ffff_c100_0010]);
}

#[cfg(target_os = "linux")]
#[test]
fn module_object_loaded_before_core_does_not_gain_kallsyms_at_uncovered_addresses() {
    assert_native_module_object_queries(&[
        0xffff_ffff_c100_0010,
        0xffff_ffff_8100_0010,
        0xffff_ffff_c100_0040,
    ]);
}

#[cfg(target_os = "linux")]
fn assert_native_module_object_queries(sampled_ips: &[u64]) {
    use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolKind, SymbolScope};
    let parent =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/native-kallsyms-fixtures");
    std::fs::create_dir_all(&parent).unwrap();
    let object_root = tempfile::tempdir_in(parent).unwrap();
    let module = object_root.path().join("a.ko");
    let mut object =
        object::write::Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    object.section_mut(text).set_data(vec![0x90; 128], 1);
    object.add_symbol(object::write::Symbol {
        name: b"loaded_module_function".to_vec(),
        value: 0,
        size: 32,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: object::write::SymbolSection::Section(text),
        flags: object::SymbolFlags::None,
    });
    let elf = object.write().unwrap();
    std::fs::write(&module, &elf).unwrap();
    let (root, bytes) = write_native_ordered_kcore_fixture(module.to_str().unwrap(), sampled_ips);
    let native_module = root
        .path()
        .join("symfs")
        .join(module.strip_prefix("/").unwrap());
    std::fs::create_dir_all(native_module.parent().unwrap()).unwrap();
    std::fs::write(native_module, elf).unwrap();
    std::fs::remove_file(root.path().join("kcore")).unwrap();
    let (script, _, native) = query_native_module_kallsyms(root.path(), &[]);
    assert!(
        script.contains("loaded_module_function+0x10 ([a])"),
        "{script}"
    );
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[cfg(target_os = "linux")]
#[test]
fn bracketed_module_first_failed_load_stays_unknown_after_ordinary_core_loading() {
    assert_module_first_queries_match_native("[a]", false);
}

#[cfg(target_os = "linux")]
#[test]
fn independent_module_sample_ip_loads_before_core_callchain_like_native_perf() {
    assert_native_independent_sample_ip(0xffff_ffff_c100_0010, 0xffff_ffff_8100_0010);
}

#[cfg(target_os = "linux")]
#[test]
fn independent_core_sample_ip_populates_modules_before_module_callchain_like_native_perf() {
    assert_native_independent_sample_ip(0xffff_ffff_8100_0010, 0xffff_ffff_c100_0010);
}

#[cfg(target_os = "linux")]
fn assert_native_independent_sample_ip(sample_ip: u64, chain_ip: u64) {
    // builtin-script.c:process_sample_event calls machine__resolve before
    // thread__resolve_callchain. The event IP need not be any chain node.
    let (root, bytes) = write_native_module_sample_and_chain_fixture(
        "ffffffff81000000 T _stext\nffffffff81000100 T _etext\n\
         ffffffffc1000000 T first\t[a]\nffffffffc1010000 T sentinel\t[b]\n",
        &[
            (sample_ip, chain_ip),
            (0xffff_ffff_c100_0010, 0xffff_ffff_c100_0010),
        ],
        false,
        ["[a]", "[b]"],
    );
    let (script, _, native) = query_native_module_kallsyms(root.path(), &[]);
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[cfg(target_os = "linux")]
#[test]
fn absolute_module_first_failed_load_stays_unknown_after_ordinary_core_loading() {
    assert_module_first_queries_match_native("/lib/modules/a.ko", false);
}

#[cfg(target_os = "linux")]
#[test]
fn bracketed_module_first_queries_follow_kcore_map_replacement() {
    assert_module_first_queries_match_native("[a]", true);
}

#[cfg(target_os = "linux")]
#[test]
fn absolute_module_first_queries_follow_kcore_map_replacement() {
    assert_module_first_queries_match_native("/lib/modules/a.ko", true);
}

#[cfg(target_os = "linux")]
fn assert_module_first_queries_match_native(module_path: &str, kcore: bool) {
    let (root, bytes) = write_native_ordered_kcore_fixture(
        module_path,
        &[
            0xffff_ffff_c100_0010,
            0xffff_ffff_c100_0010,
            0xffff_ffff_8100_0010,
            0xffff_ffff_c100_0010,
            0xffff_ffff_c100_0020,
        ],
    );
    if !kcore {
        std::fs::remove_file(root.path().join("kcore")).unwrap();
    }
    // Native dso__load marks even failed module loads as loaded;
    // maps__split_kallsyms discards rows for already-loaded modules.
    let (script, _, native) = query_native_module_kallsyms(root.path(), &[]);
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[cfg(target_os = "linux")]
#[test]
fn native_kcore_checks_absolute_and_compressed_module_addresses() {
    for module_path in [
        "/lib/modules/a.ko",
        "/lib/modules/a.ko.xz",
        "/lib/modules/a.ko.zst",
    ] {
        let (root, bytes) = write_native_kcore_fixture(module_path);
        let summary = summarize_perfdata(&bytes).unwrap();
        let mapping = summary
            .mmap_table
            .resolve_ref(11, 0xffff_ffff_c100_0010)
            .unwrap();
        std::fs::write(
            root.path().join("modules"),
            "a 16384 0 - Live 0xffffffffc1001000\nb 16384 0 - Live 0xffffffffc1010000\n",
        )
        .unwrap();
        let (script, stderr, _) = query_native_module_kallsyms(root.path(), &[]);
        assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
        assert!(
            !script.contains("first+0x10 ([kernel.kallsyms])"),
            "{script}"
        );
        let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            StaticSymbolResolver,
            &root.path().join("perf.data"),
            root.path(),
            [],
            &root.path().join("kallsyms"),
        );
        assert_eq!(resolved_kernel_dso(&resolver, &mapping), module_path);
        // Exercise the same validation through the core map, independent of
        // the module frame's absolute object path.
        let core = summary
            .mmap_table
            .resolve_ref(11, 0xffff_ffff_8100_0010)
            .unwrap();
        assert_eq!(resolved_kernel_dso(&resolver, &core), core.path);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_kcore_accepts_a_hidden_zero_relocation_reference() {
    let (root, mut bytes) = write_native_kcore_fixture("[a]");
    let name = b"[kernel.kallsyms]_stext";
    let offset = bytes
        .windows(name.len())
        .position(|bytes| bytes == name)
        .unwrap();
    put_u64(&mut bytes, offset - 8, 0);
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    let (script, stderr, _) = query_native_module_kallsyms(root.path(), &[]);
    assert!(stderr.contains("/kcore for kernel data"), "{stderr}");
    assert!(
        script.contains("first+0x10 ([kernel.kallsyms])"),
        "{script}"
    );
    let summary = summarize_perfdata(&bytes).unwrap();
    let mapping = summary
        .mmap_table
        .resolve_ref(11, 0xffff_ffff_c100_0010)
        .unwrap();
    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        StaticSymbolResolver,
        &root.path().join("perf.data"),
        root.path(),
        [],
        &root.path().join("kallsyms"),
    );
    let core = summary
        .mmap_table
        .resolve_ref(11, 0xffff_ffff_8100_0010)
        .unwrap();
    assert_eq!(resolved_kernel_dso(&resolver, &core), "[kernel.kallsyms]");
    assert_eq!(
        resolved_kernel_dso(&resolver, &mapping),
        "[kernel.kallsyms]"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn native_kcore_module_core_module_lookup_order_updates_cached_symbols() {
    const MODULE: u64 = 0xffff_ffff_c100_0010;
    const CORE: u64 = 0xffff_ffff_8100_0010;
    let (root, bytes) = write_native_kcore_fixture("[a]");
    let summary = summarize_perfdata(&bytes).unwrap();
    let data_start =
        usize::try_from(u64::from_le_bytes(bytes[40..48].try_into().unwrap())).unwrap();
    let mut offset = data_start;
    while u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) != PERF_RECORD_SAMPLE {
        offset += usize::from(u16::from_le_bytes(
            bytes[offset + 6..offset + 8].try_into().unwrap(),
        ));
    }
    let mut ordered = bytes[..offset].to_vec();
    for (index, ip) in [MODULE, CORE, MODULE].into_iter().enumerate() {
        ordered.extend(record_bytes_with_misc(
            PERF_RECORD_SAMPLE,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_time(
                ip,
                11,
                12,
                1_000_000_000 + u64::try_from(index).unwrap(),
                [0xffff_ffff_ffff_ff80, ip],
            ),
        ));
    }
    let data_size = u64::try_from(ordered.len() - data_start).unwrap();
    put_u64(&mut ordered, 48, data_size);
    std::fs::write(root.path().join("perf.data"), &ordered).unwrap();
    let (script, _, native) = query_native_module_kallsyms(root.path(), &[]);
    assert!(script.contains("[unknown] ([a])"), "{script}");
    assert!(
        script.contains("first+0x10 ([kernel.kallsyms])"),
        "{script}"
    );
    assert!(summary.mmap_table.resolve_ref(11, MODULE).is_some());
    for inline in [false, true] {
        let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            StaticSymbolResolver,
            &root.path().join("perf.data"),
            root.path(),
            [],
            &root.path().join("kallsyms"),
        );
        let actual = fold_perfdata_callchains_with_symbols(
            &ordered,
            FoldOptions {
                inline,
                count_periods: true,
            },
            &resolver,
        )
        .unwrap();
        assert_eq!(actual.as_bytes(), native, "{script}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_kcore_same_callchain_module_core_module_preserves_each_cursor_source() {
    let (root, bytes) = write_native_kcore_fixture("[a]");
    let data_start =
        usize::try_from(u64::from_le_bytes(bytes[40..48].try_into().unwrap())).unwrap();
    let mut offset = data_start;
    while u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) != PERF_RECORD_SAMPLE {
        offset += usize::from(u16::from_le_bytes(
            bytes[offset + 6..offset + 8].try_into().unwrap(),
        ));
    }
    let mut ordered = bytes[..offset].to_vec();
    ordered.extend(record_bytes_with_misc(
        PERF_RECORD_SAMPLE,
        PERF_RECORD_MISC_CPUMODE_KERNEL,
        &sample_payload_with_time(
            0xffff_ffff_c100_0010,
            11,
            12,
            1_000_000_000,
            [
                0xffff_ffff_ffff_ff80,
                0xffff_ffff_c100_0010,
                0xffff_ffff_c100_0020,
                0xffff_ffff_8100_0010,
                0xffff_ffff_c100_0010,
            ],
        ),
    ));
    let data_size = u64::try_from(ordered.len() - data_start).unwrap();
    put_u64(&mut ordered, 48, data_size);
    std::fs::write(root.path().join("perf.data"), &ordered).unwrap();
    let (script, _, native) = query_native_module_kallsyms(root.path(), &[]);
    assert!(script.contains("[unknown] ([a])"), "{script}");
    assert!(
        script.contains("first+0x10 ([kernel.kallsyms])"),
        "{script}"
    );
    for inline in [false, true] {
        let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            StaticSymbolResolver,
            &root.path().join("perf.data"),
            root.path(),
            [],
            &root.path().join("kallsyms"),
        );
        let actual = fold_perfdata_callchains_with_symbols(
            &ordered,
            FoldOptions {
                inline,
                count_periods: true,
            },
            &resolver,
        )
        .unwrap();
        assert_eq!(actual.as_bytes(), native, "{script}");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_cached_kernel_module_elf(
    root: &std::path::Path,
    shared: bool,
    data_symbol: bool,
) -> Vec<u8> {
    use std::fmt::Write as _;
    let source = root.join("module.S");
    let elf_path = root.join("module.elf");
    let mut assembly = String::from(
        ".text\n.globl cached_module_object\n.type cached_module_object,@function\ncached_module_object:\n.fill 512,1,0x90\n.size cached_module_object,.-cached_module_object\n",
    );
    if data_symbol {
        assembly.push_str(".data\n.globl module_data\n.type module_data,@object\nmodule_data:\n.quad 0\n.size module_data,.-module_data\n");
    }
    std::fs::write(&source, assembly).unwrap();
    let compiler = Command::new("cc")
        .args([
            "-nostdlib",
            if shared { "-shared" } else { "-no-pie" },
            "-Wl,-e,cached_module_object",
            "-Wl,--build-id",
            "-Wl,-Ttext=0xffffffffc1000000",
            "-o",
        ])
        .arg(&elf_path)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        compiler.status.success(),
        "{}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    let elf_bytes = std::fs::read(&elf_path).unwrap();
    let elf = object::File::parse(elf_bytes.as_slice()).unwrap();
    let id = elf.build_id().unwrap().unwrap();
    assert_eq!(id.len(), 20);
    let hex = id.iter().fold(String::new(), |mut hex, byte| {
        write!(hex, "{byte:02x}").unwrap();
        hex
    });
    let cache = pyroclast::symbols::perf_build_id_elf_path(&root.join(".debug"), &hex);
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::write(cache, &elf_bytes).unwrap();
    id.to_vec()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_native_cached_module_fixture(
    shared: bool,
    single_callchain: bool,
) -> (tempfile::TempDir, Vec<u8>) {
    write_native_cached_module_fixture_with_data(shared, single_callchain, false)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_native_cached_module_fixture_with_data(
    shared: bool,
    single_callchain: bool,
    data_symbol: bool,
) -> (tempfile::TempDir, Vec<u8>) {
    const MODULE: u64 = 0xffff_ffff_c100_0010;
    const CORE: u64 = 0xffff_ffff_8100_0010;
    let queries: &[(u64, &[u64])] = if single_callchain {
        &[(MODULE, &[MODULE, MODULE + 0x10, CORE, MODULE])]
    } else {
        &[
            (MODULE, &[MODULE]),
            (MODULE, &[MODULE]),
            (CORE, &[CORE]),
            (MODULE, &[MODULE]),
        ]
    };
    write_native_cached_module_queries(shared, data_symbol, queries)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_native_cached_module_queries(
    shared: bool,
    data_symbol: bool,
    queries: &[(u64, &[u64])],
) -> (tempfile::TempDir, Vec<u8>) {
    write_native_module_object_queries(shared, data_symbol, queries, false)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_native_module_object_queries(
    shared: bool,
    data_symbol: bool,
    queries: &[(u64, &[u64])],
    live: bool,
) -> (tempfile::TempDir, Vec<u8>) {
    use std::fmt::Write as _;

    let (root, _) = write_native_kcore_fixture("[a]");
    let id = write_cached_kernel_module_elf(root.path(), shared, data_symbol);
    let module_path = if live {
        let path = root.path().join("a.ko");
        std::fs::copy(root.path().join("module.elf"), &path).unwrap();
        let hex = id.iter().fold(String::new(), |mut hex, byte| {
            write!(hex, "{byte:02x}").unwrap();
            hex
        });
        std::fs::remove_file(pyroclast::symbols::perf_build_id_elf_path(
            &root.path().join(".debug"),
            &hex,
        ))
        .unwrap();
        path.to_str().unwrap().to_owned()
    } else {
        "[a]".to_owned()
    };
    let mut comm = comm_payload(11, 12, "worker");
    comm.resize(comm.len().next_multiple_of(8), 0);
    let mut records = vec![record_bytes(3, &comm)];
    for (start, len, pgoff, path) in [
        (
            0xffff_ffff_8100_0000,
            0x10000,
            0xffff_ffff_8100_0000,
            "[kernel.kallsyms]_stext",
        ),
        (0xffff_ffff_c101_0000, 0x4000, 0, "[b]"),
    ] {
        let mut payload = mmap_payload(u32::MAX, u32::MAX, start, len, pgoff, path);
        payload.resize(payload.len().next_multiple_of(8), 0);
        records.push(record_bytes_with_misc(
            1,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &payload,
        ));
    }
    let mut payload = mmap2_build_id_payload(
        u32::MAX,
        u32::MAX,
        0xffff_ffff_c100_0000,
        0x4000,
        0,
        &module_path,
    );
    payload[32] = 20;
    payload[36..56].copy_from_slice(&id);
    payload.resize(payload.len().next_multiple_of(8), 0);
    records.push(record_bytes_with_misc(
        10,
        PERF_RECORD_MISC_CPUMODE_KERNEL | PERF_RECORD_MISC_MMAP_BUILD_ID,
        &payload,
    ));
    for (index, &(ip, chain)) in queries.iter().enumerate() {
        let time = 1_000_000_000 + u64::try_from(index).unwrap();
        let payload = sample_payload_with_time(
            ip,
            11,
            12,
            time,
            std::iter::once(0xffff_ffff_ffff_ff80)
                .chain(chain.iter().copied())
                .collect::<Vec<_>>(),
        );
        records.push(record_bytes_with_misc(
            PERF_RECORD_SAMPLE,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &payload,
        ));
    }
    let mut attr = file_attr_bytes(
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
        0,
        0,
    );
    put_u64(&mut attr, 16, 1);
    let mut bytes = perfdata_with_records_and_attrs_vec(vec![attr], records);
    put_u64(&mut bytes, 16, 144);
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    (root, bytes)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kcore_preserves_cached_module_objects_until_core_replacement() {
    struct CountedObjectResolver {
        inner: pyroclast::symbols::RustAddr2lineResolver,
        calls: std::cell::Cell<usize>,
    }
    impl SymbolResolver for CountedObjectResolver {
        fn selected_object_module_metadata(
            &self,
            path: &std::path::Path,
            module: &SymbolRequest,
        ) -> Option<std::sync::Arc<pyroclast::symbols::KernelModuleObjectMetadata>> {
            self.inner.selected_object_module_metadata(path, module)
        }

        fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
            self.calls.set(self.calls.get() + 1);
            self.inner.resolve_batch(requests)
        }
        fn resolve_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            self.calls.set(self.calls.get() + 1);
            self.inner.resolve_frame_batch_with_metadata(requests)
        }
    }
    use inferno::collapse::Collapse as _;
    for single_callchain in [false, true] {
        let (root, bytes) = write_native_cached_module_fixture(false, single_callchain);
        let native = Command::new("perf")
            .arg("--buildid-dir")
            .arg(root.path().join(".debug"))
            .args(["script", "--force", "-vvvv", "--kallsyms"])
            .arg(root.path().join("kallsyms"))
            .arg("-i")
            .arg(root.path().join("perf.data"))
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert!(
            String::from_utf8_lossy(&native.stderr).contains("/kcore for kernel data"),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        let script = String::from_utf8(native.stdout).unwrap();
        assert_eq!(
            script.matches("cached_module_object+0x10 ([a])").count(),
            1,
            "{script}"
        );
        assert!(
            script.contains("first+0x10 ([kernel.kallsyms])"),
            "{script}"
        );
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::default()
            .collapse(script.as_bytes(), &mut expected)
            .unwrap();
        for inline in [false, true] {
            let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                CountedObjectResolver {
                    inner: pyroclast::symbols::RustAddr2lineResolver::new(),
                    calls: std::cell::Cell::new(0),
                },
                &root.path().join("perf.data"),
                root.path(),
                [],
                &root.path().join("kallsyms"),
            );
            let actual = fold_perfdata_callchains_with_symbols(
                &bytes,
                FoldOptions {
                    inline,
                    count_periods: true,
                },
                &resolver,
            )
            .unwrap();
            assert_eq!(actual.as_bytes(), expected, "{script}");
            assert_eq!(
                resolver.object_resolver().calls.get(),
                if single_callchain { 2 } else { 1 },
                "the original module object should resolve only once"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn kcore_module_object_resolution_precedes_initial_core_loading() {
    struct ObjectResolver;
    impl SymbolResolver for ObjectResolver {
        fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
            Ok(vec![Some("cached_module_object".into()); requests.len()])
        }
    }
    let (root, _) = write_native_kcore_fixture("[a]");
    let debug = root.path().join(".debug");
    let object = pyroclast::symbols::perf_build_id_elf_path(&debug, "abcdef");
    std::fs::create_dir_all(object.parent().unwrap()).unwrap();
    // Routing still validates ELF identity before delegating symbol parsing.
    let mut builder = object::build::elf::Builder::new(object::Endianness::Little, true);
    // This ELF introduces no section maps that could invalidate kcore.
    // perf validates map names and starts, not the ELF type alone.
    builder.header.e_type = object::elf::ET_REL;
    builder.header.e_machine = object::elf::EM_X86_64;
    let names = builder.sections.add();
    names.name = b".shstrtab"[..].into();
    names.sh_type = object::elf::SHT_STRTAB;
    names.sh_addralign = 1;
    names.data = object::build::elf::SectionData::SectionString;
    let note = builder.sections.add();
    note.name = b".note.gnu.build-id"[..].into();
    note.sh_type = object::elf::SHT_NOTE;
    note.sh_addralign = 4;
    note.data = object::build::elf::SectionData::Data(
        vec![
            4, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0, 0xab, 0xcd, 0xef, 0,
        ]
        .into(),
    );
    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    assert_eq!(
        object::File::parse(bytes.as_slice())
            .unwrap()
            .build_id()
            .unwrap(),
        Some(&[0xab, 0xcd, 0xef][..])
    );
    std::fs::write(object, bytes).unwrap();
    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        ObjectResolver,
        &root.path().join("perf.data"),
        root.path(),
        [],
        &root.path().join("kallsyms"),
    );
    let module = SymbolRequest {
        kernel_module_address: None,
        path: "[a]".into(),
        relative_address: 0xffff_ffff_c100_0010,
        kernel_mapping_range: Some((0xffff_ffff_c100_0000, 0xffff_ffff_c100_4000)),
        build_id: Some("abcdef".into()),
        file_identity: None,
        kernel_relocation: None,
    };
    let initial = resolver
        .resolve_frame_batch_with_metadata(std::slice::from_ref(&module))
        .unwrap();
    assert_eq!(initial[0].frames, ["cached_module_object"]);
    assert_eq!(
        initial[0].kernel_dso,
        pyroclast::symbols::SymbolDsoName::Mapping
    );
    let core = SymbolRequest {
        kernel_module_address: None,
        path: "[kernel.kallsyms]".into(),
        relative_address: 0xffff_ffff_8100_0010,
        kernel_mapping_range: Some((0xffff_ffff_8100_0000, 0xffff_ffff_8101_0000)),
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    assert_eq!(
        resolver.resolve_frame_batch_with_metadata(&[core]).unwrap()[0].kernel_dso,
        pyroclast::symbols::SymbolDsoName::KernelKallsyms
    );
    let later = resolver
        .resolve_frame_batch_with_metadata(&[module])
        .unwrap();
    assert_eq!(later[0].frames, ["first+0x10"]);
    assert_eq!(
        later[0].kernel_dso,
        pyroclast::symbols::SymbolDsoName::KernelKallsyms
    );
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_ignores_dollar_symbols_before_global_end_fixup_like_native_perf() {
    // tools/perf/util/symbol.c:774 rejects '$' names before tree insertion;
    // symbols__fixup_end:295 consequently ends first[a] at next[a], not a
    // page boundary. symbols__find:414 treats that end as exclusive.
    assert_native_module_kallsyms_queries_parity(
        "ffffffff81000000 T _stext\n\
         ffffffff81000100 T _etext\n\
         ffffffffc1000000 T first\t[a]\n\
         ffffffffc1000100 t $x\n\
         ffffffffc1000200 T next\t[a]\n\
         ffffffffc1010000 T sentinel\t[b]\n",
        &[0xffff_ffff_c100_0180, 0xffff_ffff_c100_0200],
        Some("worker;_stext 1\nworker;first 1\nworker;next 1\n"),
        &[("first\t[a]", 0xffff_ffff_c100_0200)],
    );
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_core_boundary_limits_extent_before_partition_like_native_perf() {
    // symbol.c:1512-1513 fixes ends then duplicates on ALL accepted symbols.
    // The core entry makes first[a] end at c1001000, not next[a] at c1002000.
    assert_native_module_kallsyms_parity(
        "ffffffff81000000 T _stext\n\
         ffffffff81000100 T _etext\n\
         ffffffffc1000000 T first\t[a]\n\
         ffffffffc1000100 T core_boundary\n\
         ffffffffc1002000 T next\t[a]\n\
         ffffffffc1010000 T sentinel\t[b]\n",
        0xffff_ffff_c100_1800,
        "[[a]]",
        &[("first\t[a]", 0xffff_ffff_c100_1000)],
    );
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_equal_address_alias_keeps_native_nonweak_module_owner() {
    // symbol.c:__symbols__insert preserves ties; fixup_end gives both owners
    // nonzero lengths. choose_best_symbol then prefers T over weak W, even
    // though the W entry was inserted later. Split only the surviving owner.
    assert_native_module_kallsyms_parity(
        "ffffffff81000000 T _stext\n\
         ffffffff81000100 T _etext\n\
         ffffffffc1000000 T strong\t[a]\n\
         ffffffffc1000000 W weak\t[b]\n\
         ffffffffc1000100 T next\t[a]\n\
         ffffffffc1010000 T sentinel\t[b]\n",
        0xffff_ffff_c100_0020,
        "strong",
        &[
            ("strong\t[a]", 0xffff_ffff_c100_1000),
            ("weak\t[b]", 0xffff_ffff_c100_1000),
        ],
    );
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_discarded_alias_preserves_native_predecessor_extent_and_lookup() {
    // End fixup precedes duplicate removal, so weak[b] changes previous[a]'s
    // extent even though winner[a] removes it. Native symbols__find searches
    // the split DSO's RB tree; with these two entries, previous is its root
    // and contains the sampled IP despite winner starting before that IP.
    assert_native_module_kallsyms_parity(
        "ffffffff81000000 T _stext\n\
         ffffffff81000100 T _etext\n\
         ffffffffc1000000 T previous\t[a]\n\
         ffffffffc1000100 W weak\t[b]\n\
         ffffffffc1000100 T winner\t[a]\n\
         ffffffffc1010000 T sentinel\t[b]\n",
        0xffff_ffff_c100_0180,
        "previous",
        &[
            ("previous\t[a]", 0xffff_ffff_c100_1000),
            ("weak\t[b]", 0xffff_ffff_c100_2000),
            ("winner\t[a]", 0xffff_ffff_c100_2000),
        ],
    );
}

#[cfg(target_os = "linux")]
fn overlapping_module_kallsyms_fixture(row_count: usize) -> (String, Vec<(String, u64)>) {
    use std::fmt::Write as _;

    const START: u64 = 0xffff_ffff_c100_0000;
    let mut text = "ffffffff81000000 T _stext\nffffffff81000100 T _etext\n".to_string();
    let mut ends = Vec::new();
    for index in 0..row_count {
        let address = START + u64::try_from(index).expect("row index") * 0x100;
        let name = format!("row_{index:02}");
        writeln!(text, "{address:016x} T {name}\t[a]").expect("module row");
        writeln!(text, "{:016x} T core_{index:02}", address + 0x80).expect("core boundary");
        // symbol.c:symbols__fixup_end rounds a module-to-core transition to
        // roundup(start + 4096, 4096), before maps__split_kallsyms partitions.
        ends.push((format!("{name}\t[a]"), (address + 0x1fff) & !0xfff));
    }
    text.push_str("ffffffffc1010000 T sentinel\t[b]\n");
    (text, ends)
}

#[cfg(target_os = "linux")]
fn assert_native_overlapping_module_tree_parity(row_count: usize) {
    const START: u64 = 0xffff_ffff_c100_0000;
    let (text, ends) = overlapping_module_kallsyms_fixture(row_count);
    let expected_ends = ends
        .iter()
        .map(|(name, end)| (name.as_str(), *end))
        .collect::<Vec<_>>();
    let mut queries = vec![START + 0xf80];
    for index in 0..row_count {
        let start = START + u64::try_from(index).expect("row index") * 0x100;
        // Start-minus-one and start probe left-subtree descent; start-plus-one
        // also catches the erroneous greatest-start/predecessor preference.
        if start > START {
            queries.push(start - 1);
        }
        queries.extend([start, start + 1]);
    }
    // Probe both fixed extents on each side of their half-open boundary,
    // including right-subtree descent and the unmapped symbol gap in [a].
    queries.extend([
        START + 0xfff,
        START + 0x1000,
        START + 0x1001,
        START + 0x1fff,
        START + 0x2000,
        START + 0x2001,
        START + 0x3000,
    ]);
    queries.sort_unstable();
    queries.dedup();
    assert_native_module_kallsyms_queries_parity(&text, &queries, None, &expected_ends);
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_two_overlapping_rows_match_native_tree_boundaries() {
    assert_native_overlapping_module_tree_parity(2);
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_three_overlapping_rows_return_native_middle_root_not_lowest_start() {
    // Linux tools/lib/rbtree.c:__rb_insert rotates three ascending insertions
    // to root row_01. All three extents contain c1000f80; lowest-start is wrong.
    let (text, ends) = overlapping_module_kallsyms_fixture(3);
    let expected_ends = ends
        .iter()
        .map(|(name, end)| (name.as_str(), *end))
        .collect::<Vec<_>>();
    assert_native_module_kallsyms_parity(&text, 0xffff_ffff_c100_0f80, "row_01", &expected_ends);
    assert_native_overlapping_module_tree_parity(3);
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_four_overlapping_rows_match_native_tree_boundaries() {
    assert_native_overlapping_module_tree_parity(4);
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_eight_overlapping_rows_match_native_tree_boundaries() {
    assert_native_overlapping_module_tree_parity(8);
}

#[cfg(target_os = "linux")]
#[test]
fn module_kallsyms_sixteen_overlapping_rows_match_native_tree_boundaries() {
    assert_native_overlapping_module_tree_parity(16);
}

#[cfg(target_os = "linux")]
#[test]
fn hypervisor_callchain_context_does_not_resolve_host_user_mappings_like_perf() {
    // tools/perf/util/machine.c:add_callchain_ip switches PERF_CONTEXT_HV to
    // PERF_RECORD_MISC_HYPERVISOR. util/event.c:thread__find_map returns NULL
    // for that mode; Inferno perf.rs:with_module_fallback keeps [unknown].
    let bytes = callchain_context_fixture(&[
        0xffff_ffff_ffff_fe00,
        0x1010,
        0xffff_ffff_ffff_ffe0,
        0x1020,
        0xffff_ffff_ffff_fe00,
        0x1030,
    ]);
    let (script, expected) = native_script_and_fold(&bytes);
    assert_eq!(expected, "worker;[app];[unknown];[app] 1\n", "{script}");
    assert_eq!(
        fold_perfdata_callchains(&bytes).expect("fold"),
        expected,
        "native script={script}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn invalid_callchain_context_discards_all_recorded_frames_like_perf() {
    // tools/perf/util/machine.c:add_callchain_ip resets the entire cursor and
    // returns 1 on unsupported PERF_CONTEXT_* values; its caller stops then.
    for marker in [0xffff_ffff_ffff_f001, 0xffff_ffff_ffff_f800, u64::MAX] {
        let bytes = callchain_context_fixture(&[0x1010, marker, 0x1020]);
        let (script, expected) = native_script_and_fold(&bytes);
        assert_eq!(
            fold_perfdata_callchains(&bytes).expect("fold"),
            expected,
            "marker={marker:x}; native script={script}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn address_immediately_below_perf_context_max_remains_a_frame_like_perf() {
    // include/uapi/linux/perf_event.h defines PERF_CONTEXT_MAX as (u64)-4095,
    // not -4096. machine.c:add_callchain_ip treats the latter as a real IP.
    let bytes = callchain_context_fixture(&[0x1010, 0xffff_ffff_ffff_f000, 0x1020]);
    let (script, expected) = native_script_and_fold(&bytes);
    assert_eq!(expected, "worker;[app];[unknown];[app] 1\n", "{script}");
    assert_eq!(
        fold_perfdata_callchains(&bytes).expect("fold"),
        expected,
        "native script={script}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn invalid_context_beyond_perf_default_stack_depth_does_not_discard_the_prefix() {
    // trace-event-scripting.c:24 initializes scripting_max_stack to
    // PERF_MAX_STACK_DEPTH (127). machine.c:2899 counts addresses, not markers.
    let mut frames = [0x1010; 128];
    frames[127] = u64::MAX;
    let bytes = callchain_context_fixture(&frames);
    let (script, expected) = native_script_and_fold(&bytes);
    assert_eq!(
        expected,
        format!("worker{} 1\n", ";[app]".repeat(127)),
        "{script}"
    );
    assert_eq!(
        fold_perfdata_callchains(&bytes).expect("fold"),
        expected,
        "{script}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn context_markers_do_not_consume_perf_default_recorded_stack_depth() {
    let mut frames = [0x1010; 256];
    for marker in frames.iter_mut().step_by(2) {
        *marker = 0xffff_ffff_ffff_fe00;
    }
    let bytes = callchain_context_fixture(&frames);
    let (script, expected) = native_script_and_fold(&bytes);
    assert_eq!(
        expected,
        format!("worker{} 1\n", ";[app]".repeat(127)),
        "{script}"
    );
    assert_eq!(
        fold_perfdata_callchains(&bytes).expect("fold"),
        expected,
        "{script}"
    );
}

#[cfg(target_os = "linux")]
fn callchain_context_fixture<const N: usize>(frames: &[u64; N]) -> Vec<u8> {
    let mut comm = comm_payload(11, 12, "worker");
    comm.resize(comm.len().next_multiple_of(8), 0);
    let mut mmap = mmap_payload(11, 11, 0x1000, 0x100, 0, "/pyroclast-missing-context/app");
    mmap.resize(mmap.len().next_multiple_of(8), 0);
    perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_TIME
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm),
            record_bytes_with_misc(1, PERF_RECORD_MISC_CPUMODE_USER, &mmap),
            record_bytes_with_misc(
                PERF_RECORD_SAMPLE,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample_payload_with_optional_timestamp(
                    sample_payload_with_period(0x1010, 11, 12, 1, *frames),
                    true,
                ),
            ),
        ],
    )
}

#[cfg(target_os = "linux")]
#[test]
fn deferred_markers_without_attr_flag_leave_the_cookie_as_a_recorded_frame() {
    assert_deferred_context_matches_native(false, 0x1040, None);
}

#[cfg(target_os = "linux")]
#[test]
fn deferred_cookie_eof_preserves_native_context_validation_and_cookie_suppression() {
    for cookie in [0x1040, 0x1010, u64::MAX, 0xffff_ffff_ffff_ffe0] {
        assert_deferred_context_matches_native(true, cookie, None);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn matching_deferred_records_merge_before_context_validation_like_perf() {
    for cookie in [0x1040, u64::MAX, 0xffff_ffff_ffff_ffe0] {
        assert_deferred_context_matches_native(true, cookie, Some((cookie, 12)));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn same_tid_deferred_cookie_mismatch_delivers_original_cookie_as_an_address_like_perf() {
    assert_deferred_context_matches_native(true, 0x1040, Some((0x5555, 12)));
}

#[cfg(target_os = "linux")]
#[test]
fn different_tid_deferred_record_leaves_original_metadata_for_eof_like_perf() {
    assert_deferred_context_matches_native(true, 0x1040, Some((0x1040, 99)));
}

#[cfg(target_os = "linux")]
fn assert_deferred_context_matches_native(
    enabled: bool,
    cookie: u64,
    deferred: Option<(u64, u32)>,
) {
    assert_deferred_context_with_cookie_mapping_matches_native(enabled, cookie, deferred, None);
}

#[cfg(target_os = "linux")]
#[test]
fn deferred_cookie_dso_preserves_physical_stream_rows_like_perf_and_inferno() {
    // evsel_fprintf.c prints the DSO even for a (cookie) row. map.c writes
    // the name verbatim; Inferno reads physical lines before omitting cookies.
    assert_deferred_context_with_cookie_mapping_matches_native(
        true,
        0x1040,
        None,
        Some("/missing/a\n0010 injected (/bin/n)"),
    );
}

#[cfg(target_os = "linux")]
fn assert_deferred_context_with_cookie_mapping_matches_native(
    enabled: bool,
    cookie: u64,
    deferred: Option<(u64, u32)>,
    cookie_mapping: Option<&str>,
) {
    // evsel.c:3391 gates deferred metadata on attr.defer_callchain (bit38).
    // session.c:1392 and callchain.c:1897 deliver mismatches unchanged and
    // remove the original cookie only on a matching merge, before resolution.
    let mut comm = comm_payload(11, 12, "worker");
    comm.resize(comm.len().next_multiple_of(8), 0);
    let mut mmap = mmap_payload(11, 11, 0x1000, 0x100, 0, "/pyroclast-missing-context/app");
    mmap.resize(mmap.len().next_multiple_of(8), 0);
    for payload in [&mut comm, &mut mmap] {
        payload.extend(11_u32.to_le_bytes());
        payload.extend(12_u32.to_le_bytes());
        payload.extend(1_000_000_000_u64.to_le_bytes());
    }
    let mut records = vec![
        record_bytes(3, &comm),
        record_bytes_with_misc(1, PERF_RECORD_MISC_CPUMODE_USER, &mmap),
        record_bytes_with_misc(
            PERF_RECORD_SAMPLE,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_optional_timestamp(
                sample_payload_with_period(
                    0x1010,
                    11,
                    12,
                    1,
                    [0x1010, 0x1020, 0xffff_ffff_ffff_fd80, cookie],
                ),
                true,
            ),
        ),
    ];
    if let Some(path) = cookie_mapping {
        let mut payload = mmap_payload(11, 11, cookie, 16, 0, path);
        payload.resize(payload.len().next_multiple_of(8), 0);
        payload.extend(11_u32.to_le_bytes());
        payload.extend(12_u32.to_le_bytes());
        payload.extend(1_000_000_000_u64.to_le_bytes());
        records.insert(
            2,
            record_bytes_with_misc(1, PERF_RECORD_MISC_CPUMODE_USER, &payload),
        );
    }
    if let Some((record_cookie, tid)) = deferred {
        let mut payload = callchain_deferred_payload(record_cookie, [0x1030]);
        payload.extend(11_u32.to_le_bytes());
        payload.extend(tid.to_le_bytes());
        payload.extend(1_000_000_001_u64.to_le_bytes());
        records.push(record_bytes(22, &payload));
    }
    let bytes = perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes_with_flags(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_TIME
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            (1 << 18) | if enabled { 1 << 38 } else { 0 },
        )],
        records,
    );
    let (script, expected) = native_script_and_fold(&bytes);
    if cookie_mapping.is_some() {
        assert!(
            expected.contains("injected"),
            "native script={script}; folded={expected}"
        );
    }
    assert_eq!(
        fold_perfdata_callchains(&bytes).expect("fold"),
        expected,
        "enabled={enabled}, cookie={cookie:x}, deferred={deferred:?}; native script={script}"
    );
    let root = tempfile::tempdir().expect("tempdir");
    let input = root.path().join("perf.data");
    std::fs::write(&input, bytes).expect("write fixture");
    assert_eq!(
        fold_perfdata_file_with_options(&input, FoldOptions::default()).expect("file fold"),
        expected,
        "native script={script}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn callchains_without_tid_follow_native_inferno_header_parsing() {
    // builtin-script.c:evsel__check_attr (TID check) removes PID/TID when
    // PERF_SAMPLE_TID is absent. Inferno perf.rs:event_line_parts then finds
    // any other numeric word, not a fixed TID column.
    for timed in [false, true] {
        let mut sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN;
        let mut payload = 0x2000_u64.to_le_bytes().to_vec();
        if timed {
            sample_type |= PERF_SAMPLE_TIME;
            payload.extend(1_000_000_000_u64.to_le_bytes());
        }
        payload.extend(7_u64.to_le_bytes());
        payload.extend(1_u64.to_le_bytes());
        payload.extend(0x2000_u64.to_le_bytes());
        let bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes(sample_type, 0, 0)],
            [record_bytes_with_misc(
                PERF_RECORD_SAMPLE,
                PERF_RECORD_MISC_CPUMODE_USER,
                &payload,
            )],
        );
        let (script, expected) = native_script_and_fold(&bytes);
        let actual = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions {
                count_periods: true,
                inline: false,
            },
        )
        .expect("fold");
        assert_eq!(actual, expected, "timed={timed}; native script={script}");
    }
}

fn overflowing_period_fixture() -> Vec<u8> {
    period_accumulation_fixture([u64::MAX, 1], None)
}

fn period_accumulation_fixture(periods: [u64; 2], comm: Option<&str>) -> Vec<u8> {
    let mut records = Vec::new();
    if let Some(comm) = comm {
        records.push(record_bytes(3, &comm_payload(11, 12, comm)));
    }
    records.extend(periods.map(|period| {
        record_bytes_with_misc(
            PERF_RECORD_SAMPLE,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_optional_timestamp(
                sample_payload_with_period(0x2000, 11, 12, period, [0x2000]),
                true,
            ),
        )
    }));
    perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_TIME
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        records,
    )
}

#[test]
fn period_overflow_saturates_byte_folding_like_profile_summaries() {
    let bytes = overflowing_period_fixture();
    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .unwrap();
    assert_eq!(folded, format!(":12;[unknown] {}\n", u64::MAX));
    let summary =
        pyroclast::summary::summarize_perfdata_profile(&bytes, 1_000_000_000, 10).unwrap();
    assert_eq!(summary.weighted_samples, u64::MAX);
    assert_eq!(summary.threads[0].weighted_samples, u64::MAX);
}

#[test]
fn period_overflow_saturates_file_folding_like_streamed_profile_summaries() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), overflowing_period_fixture()).unwrap();
    let folded = fold_perfdata_file_with_options(
        file.path(),
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .unwrap();
    assert_eq!(folded, format!(":12;[unknown] {}\n", u64::MAX));
    let summary =
        pyroclast::summary::summarize_perfdata_profile_file(file.path(), 1_000_000_000, 10)
            .unwrap();
    assert_eq!(summary.weighted_samples, u64::MAX);
    assert_eq!(summary.threads[0].weighted_samples, u64::MAX);
}

#[test]
fn whole_stream_period_overflow_saturates_byte_folding_like_direct_folding() {
    // A COMM newline requires one continuous Inferno parser. Its perf.rs
    // after_event (574-597) reaches common.rs insert_or_add (410-416): the
    // same documented saturation policy must apply there, not just directly.
    let options = FoldOptions {
        count_periods: true,
        inline: false,
    };
    for (periods, total) in [([7, 3], 10), ([u64::MAX, 1], u64::MAX)] {
        let bytes = period_accumulation_fixture(periods, Some("worker\ntask"));
        assert_eq!(
            fold_perfdata_callchains_with_options(&bytes, options).unwrap(),
            format!("task;[unknown] {total}\n"),
        );
    }
}

#[test]
fn whole_stream_period_overflow_saturates_file_folding_like_direct_folding() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let options = FoldOptions {
        count_periods: true,
        inline: false,
    };
    for (periods, total) in [([7, 3], 10), ([u64::MAX, 1], u64::MAX)] {
        std::fs::write(
            file.path(),
            period_accumulation_fixture(periods, Some("worker\ntask")),
        )
        .unwrap();
        assert_eq!(
            fold_perfdata_file_with_options(file.path(), options).unwrap(),
            format!("task;[unknown] {total}\n"),
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn absent_sample_period_uses_event_attribute_default_like_real_perf() {
    // tools/perf/util/evsel.c:evsel__parse_sample (3232) initializes period
    // from attr.sample_period; only PERF_SAMPLE_PERIOD (3322) overrides it.
    for default_period in [0, 1, 37] {
        let mut attr = file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        );
        put_u64(&mut attr, 16, default_period);
        let mut comm = comm_payload(11, 12, "worker");
        comm.resize(comm.len().next_multiple_of(8), 0);
        let bytes = perfdata_with_records_and_attrs(
            [attr],
            [
                record_bytes(3, &comm),
                record_bytes_with_misc(
                    PERF_RECORD_SAMPLE,
                    PERF_RECORD_MISC_CPUMODE_USER,
                    &sample_payload_with_time(0x2000, 11, 12, 1_000_000_000, [0x2000]),
                ),
            ],
        );
        let (script, expected) = native_script_and_fold(&bytes);
        let actual = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions {
                count_periods: true,
                inline: false,
            },
        )
        .expect("fold");
        assert_eq!(
            actual, expected,
            "default={default_period}; native script={script}"
        );
        let root = tempfile::tempdir().expect("tempdir");
        let input = root.path().join("perf.data");
        std::fs::write(&input, &bytes).expect("write fixture");
        let file_folded = fold_perfdata_file_with_options(
            &input,
            FoldOptions {
                count_periods: true,
                inline: false,
            },
        )
        .expect("fold file");
        assert_eq!(file_folded, expected);
        assert_eq!(
            fold_perfdata_callchains(&bytes).expect("unweighted fold"),
            "worker;[unknown] 1\n"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn aliased_overlapping_attribute_ids_select_the_latest_event_like_native_perf() {
    // tools/lib/perf/evlist.c:perf_evlist__id_hash inserts at the hash-list
    // head; util/evlist.c:evlist__id2sid returns the first matching ID.
    let mask = PERF_SAMPLE_IDENTIFIER
        | PERF_SAMPLE_IP
        | PERF_SAMPLE_TID
        | PERF_SAMPLE_TIME
        | PERF_SAMPLE_CALLCHAIN;
    let mut attrs = [
        file_attr_bytes_with_ids(mask, 536, [111, 222]),
        file_attr_bytes_with_ids(mask, 544, [222, 333]),
        file_attr_bytes_with_ids(mask, 536, [111, 222]),
    ];
    for (attr, period) in attrs.iter_mut().zip([37, 99, 11]) {
        put_u64(attr, 16, period);
    }
    let records = [111_u64, 222, 333].map(|identifier| {
        let mut payload = identifier.to_le_bytes().to_vec();
        payload.extend(sample_payload_with_time(
            0x2000,
            11,
            12,
            1_000_000_000,
            [0x2000],
        ));
        record_bytes_with_misc(PERF_RECORD_SAMPLE, PERF_RECORD_MISC_CPUMODE_USER, &payload)
    });
    let mut bytes = perfdata_with_attrs_ids_and_records(attrs, [111, 222, 333], records);
    put_u64(&mut bytes, 16, 144);
    let (script, expected) = native_script_and_fold(&bytes);
    assert_eq!(expected, ":12;[unknown] 121\n", "native script={script}");
    let options = FoldOptions {
        count_periods: true,
        inline: false,
    };
    assert_eq!(
        fold_perfdata_callchains_with_options(&bytes, options).unwrap(),
        expected
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    assert_eq!(
        fold_perfdata_file_with_options(file.path(), options).unwrap(),
        expected
    );
}

#[cfg(target_os = "linux")]
#[test]
fn absent_sample_period_uses_the_selected_identifier_events_default() {
    let mask = PERF_SAMPLE_IDENTIFIER
        | PERF_SAMPLE_IP
        | PERF_SAMPLE_TID
        | PERF_SAMPLE_TIME
        | PERF_SAMPLE_CALLCHAIN;
    let mut first = file_attr_bytes_with_ids(mask, 392, [111]);
    let mut second = file_attr_bytes_with_ids(mask, 400, [222]);
    put_u64(&mut first, 16, 37);
    put_u64(&mut second, 16, 99);
    let records = [222_u64, 111].map(|identifier| {
        let mut payload = identifier.to_le_bytes().to_vec();
        payload.extend(sample_payload_with_time(
            0x2000,
            11,
            12,
            1_000_000_000,
            [0x2000],
        ));
        record_bytes_with_misc(PERF_RECORD_SAMPLE, PERF_RECORD_MISC_CPUMODE_USER, &payload)
    });
    let bytes = perfdata_with_attrs_ids_and_records([first, second], [111, 222], records);
    let (script, expected) = native_script_and_fold(&bytes);
    let weighted = FoldOptions {
        count_periods: true,
        inline: false,
    };
    let actual = fold_perfdata_callchains_with_options(&bytes, weighted).expect("fold");
    assert_eq!(actual, expected, "native script={script}");
    assert_eq!(actual, ":12;[unknown] 136\n");
    let root = tempfile::tempdir().expect("tempdir");
    let input = root.path().join("perf.data");
    std::fs::write(&input, bytes).expect("write fixture");
    assert_eq!(
        fold_perfdata_file_with_options(&input, weighted).expect("fold file"),
        actual
    );
}

#[cfg(target_os = "linux")]
#[test]
fn newline_elf_symbol_names_follow_native_perf_and_inferno_row_boundaries() {
    assert_elf_symbol_text_matches_native_pipeline("entry");
    assert_elf_symbol_text_matches_native_pipeline("entry\nsuffix");
}

#[cfg(target_os = "linux")]
#[test]
fn leading_whitespace_in_elf_symbols_follows_native_inferno_row_trimming() {
    for name in [" \tentry", " ", "\tentry", "\u{2003}entry", "entry "] {
        assert_elf_symbol_text_matches_native_pipeline(name);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn interior_carriage_returns_in_elf_symbols_are_preserved_like_native_inferno() {
    assert_elf_symbol_text_matches_native_pipeline("entry\rsuffix");
}

#[cfg(target_os = "linux")]
fn compiled_elf_with_symbol_text(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    let source = root.path().join("fixture.c");
    let original = root.path().join("original");
    let elf = root.path().join("renamed");
    std::fs::write(
        &source,
        "void entry(void) {} int main(void) { entry(); return 0; }",
    )
    .expect("write C");
    let compiled = Command::new("cc")
        .args(["-g0", "-O0", "-no-pie"])
        .arg(&source)
        .arg("-o")
        .arg(&original)
        .output()
        .expect("compile fixture");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let renamed = Command::new("objcopy")
        .arg("--redefine-sym")
        .arg(format!("entry={name}"))
        .arg(&original)
        .arg(&elf)
        .output()
        .expect("rename ELF symbol");
    assert!(
        renamed.status.success(),
        "{}",
        String::from_utf8_lossy(&renamed.stderr)
    );
    (root, elf)
}

#[cfg(target_os = "linux")]
fn assert_elf_symbol_text_matches_native_pipeline(name: &str) {
    // util/symbol_fprintf.c:__symbol__fprintf_symname_offs prints sym->name
    // verbatim; Inferno reads physical lines before stack_line_parts trims.
    let (root, elf) = compiled_elf_with_symbol_text(name);
    let object_bytes = std::fs::read(&elf).expect("read ELF");
    let object = object::File::parse(&object_bytes[..]).expect("parse ELF");
    let symbol = object
        .symbols()
        .find(|symbol| symbol.name() == Ok(name))
        .expect("renamed symbol");
    let segment = object
        .segments()
        .find(|segment| {
            segment.address() <= symbol.address()
                && symbol.address() < segment.address() + segment.size()
        })
        .expect("symbol segment");
    let (pgoff, len) = segment.file_range();
    let start = 0x7000_0000 + pgoff;
    let ip = start + symbol.address() - segment.address();
    let mut mmap = mmap_payload(11, 12, start, len, pgoff, elf.to_str().expect("ELF path"));
    mmap.resize(mmap.len().next_multiple_of(8), 0);
    let sample = record_bytes_with_misc(
        PERF_RECORD_SAMPLE,
        PERF_RECORD_MISC_CPUMODE_USER,
        &sample_payload_with_optional_timestamp(
            sample_payload_with_period(ip, 11, 12, 7, [ip]),
            true,
        ),
    );
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_TIME
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(1, PERF_RECORD_MISC_CPUMODE_USER, &mmap),
            sample.clone(),
            sample,
        ],
    );
    let (script, expected) = native_script_and_fold(&bytes);
    assert!(
        script.contains(name),
        "native must resolve ELF symbol: {script}"
    );
    let input = root.path().join("perf.data");
    std::fs::write(&input, &bytes).expect("write perf.data");
    for inline in [false, true] {
        let options = FoldOptions {
            count_periods: true,
            inline,
        };
        let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(
            pyroclast::symbols::RustAddr2lineResolver::new(),
        );
        let actual =
            fold_perfdata_callchains_with_symbols(&bytes, options, &resolver).expect("fold");
        assert_eq!(
            actual, expected,
            "symbol={name:?}, inline={inline}; native script={script}"
        );
        let file_backed =
            pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(&input, options, &resolver)
                .expect("fold file");
        assert_eq!(
            file_backed, expected,
            "symbol={name:?}, inline={inline}; native script={script}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn multiline_event_names_preserve_native_infernos_first_event_filter() {
    // util/header.c:read_event_desc retains the name; builtin-script.c:
    // process_event prints it with %*s. Inferno process_single_stack splits LF
    // before on_event_line chooses the first event token for the whole stream.
    for name in ["cycles\nsuffix", "cycles\n\nsuffix", "cycles\n#comment"] {
        let mask = PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN;
        let attrs = [
            file_attr_bytes_with_ids(mask, 392, [111]),
            file_attr_bytes_with_ids(mask, 400, [222]),
        ];
        let records = [111_u64, 222].map(|identifier| {
            let mut payload = identifier.to_le_bytes().to_vec();
            payload.extend(sample_payload_with_optional_timestamp(
                sample_payload_with_period(0x2000, 11, 12, 7, [0x2000]),
                true,
            ));
            record_bytes_with_misc(PERF_RECORD_SAMPLE, PERF_RECORD_MISC_CPUMODE_USER, &payload)
        });
        let mut bytes = perfdata_with_attrs_ids_and_records(attrs, [111, 222], records);
        // HEADER_EVENT_DESC (12): nre, attr_sz, then attr, nr, name, ids.
        let mut feature = Vec::new();
        feature.extend_from_slice(&2_u32.to_le_bytes());
        feature.extend_from_slice(&128_u32.to_le_bytes());
        for (attr, event_name) in attrs.iter().zip([name, "cycles"]) {
            feature.extend_from_slice(&attr[..128]);
            feature.extend_from_slice(&0_u32.to_le_bytes());
            let len = (event_name.len() + 1).next_multiple_of(64);
            feature.extend_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
            let start = feature.len();
            feature.extend_from_slice(event_name.as_bytes());
            feature.resize(start + len, 0);
        }
        let table = bytes.len();
        bytes.resize(table + 16, 0);
        put_u64(&mut bytes, 72, 1 << 12);
        put_u64(&mut bytes, table, (table + 16) as u64);
        put_u64(&mut bytes, table + 8, feature.len() as u64);
        bytes.extend(feature);
        let (script, expected) = native_script_and_fold(&bytes);
        assert!(
            script.contains(name),
            "native must use EVENT_DESC: {script}"
        );
        let options = FoldOptions {
            count_periods: true,
            inline: false,
        };
        let actual = fold_perfdata_callchains_with_options(&bytes, options).expect("fold");
        assert_eq!(actual, expected, "event={name:?}; native script={script}");
        let root = tempfile::tempdir().expect("tempdir");
        let input = root.path().join("perf.data");
        std::fs::write(&input, bytes).expect("write fixture");
        assert_eq!(
            fold_perfdata_file_with_options(&input, options).expect("fold file"),
            expected,
            "event={name:?}; native script={script}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn numeric_words_in_comms_follow_infernos_first_numeric_header_word() {
    // perf prints comm verbatim (builtin-script.c:perf_sample__fprintf_start).
    // Inferno event_line_parts recognizes digits/slashes after literal spaces.
    for timed in [false, true] {
        for name in [
            "work 123 task",
            "work 123",
            "work 12/34 task",
            "123 worker",
            "work 123 tag:",
            "work / task",
            "work ١ task",
            "work\t123 task",
        ] {
            let mut comm = comm_payload(11, 12, name);
            comm.resize(comm.len().next_multiple_of(8), 0);
            let bytes = perfdata_with_records_and_attrs(
                [file_attr_bytes(
                    PERF_SAMPLE_IP
                        | PERF_SAMPLE_TID
                        | PERF_SAMPLE_PERIOD
                        | PERF_SAMPLE_CALLCHAIN
                        | if timed { PERF_SAMPLE_TIME } else { 0 },
                    0,
                    0,
                )],
                [
                    record_bytes(3, &comm),
                    record_bytes_with_misc(
                        PERF_RECORD_SAMPLE,
                        PERF_RECORD_MISC_CPUMODE_USER,
                        &sample_payload_with_optional_timestamp(
                            sample_payload_with_period(0x2000, 11, 12, 7, [0x2000]),
                            timed,
                        ),
                    ),
                ],
            );
            let (script, expected) = native_script_and_fold(&bytes);
            let actual = fold_perfdata_callchains_with_options(
                &bytes,
                FoldOptions {
                    count_periods: true,
                    inline: false,
                },
            )
            .expect("fold");
            assert_eq!(
                actual, expected,
                "name={name:?}, timed={timed}; native script={script}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn without_sample_id_all_metadata_and_timed_samples_follow_native_input_order() {
    // util/session.c:perf_session__new disables ordered_events when timestamps
    // are required but evlist__sample_id_all is false.
    let mut records = Vec::new();
    for (name, period) in [("before", 3), ("after", 7)] {
        let mut comm = comm_payload(11, 12, name);
        comm.resize(comm.len().next_multiple_of(8), 0);
        records.push(record_bytes(3, &comm));
        records.push(record_bytes_with_misc(
            PERF_RECORD_SAMPLE,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_optional_timestamp(
                sample_payload_with_period(0x2000, 11, 12, period, [0x2000]),
                true,
            ),
        ));
    }
    let bytes = perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_TIME
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        records,
    );
    let (script, expected) = native_script_and_fold(&bytes);
    let options = FoldOptions {
        count_periods: true,
        inline: false,
    };
    assert_eq!(expected, "after;[unknown] 7\nbefore;[unknown] 3\n");
    let actual = fold_perfdata_callchains_with_options(&bytes, options).expect("fold");
    assert_eq!(actual, expected, "native script={script}");
    let root = tempfile::tempdir().expect("tempdir");
    let input = root.path().join("perf.data");
    std::fs::write(&input, bytes).expect("write fixture");
    assert_eq!(
        fold_perfdata_file_with_options(&input, options).expect("fold file"),
        expected
    );
}

#[cfg(target_os = "linux")]
#[test]
fn comment_comm_headers_follow_native_inferno_line_skipping() {
    for name in ["#worker", " #worker", "worker#task"] {
        assert_structural_comm_matches_native_stream(name);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn newline_comm_headers_follow_native_inferno_line_boundaries() {
    assert_structural_comm_matches_native_stream("worker\ntask");
}

#[cfg(target_os = "linux")]
#[test]
fn blank_lines_in_comm_headers_follow_native_inferno_event_boundaries() {
    assert_structural_comm_matches_native_stream("worker\n\ntask");
}

#[cfg(target_os = "linux")]
fn assert_structural_comm_matches_native_stream(name: &str) {
    // builtin-script.c:perf_sample__fprintf_start prints comm with %s.
    // Inferno process_single_stack ignores # lines and splits at newlines;
    // after_event does not clear pname, so the preceding header matters.
    for (time, sample_id_all) in [
        (0_u64, false),
        (0, true),
        (1_000_000_000, false),
        (1_000_000_000, true),
    ] {
        let mut records = Vec::new();
        for (comm, period) in [("before", 3), (name, 7), ("after", 11)] {
            let mut payload = comm_payload(11, 12, comm);
            payload.resize(payload.len().next_multiple_of(8), 0);
            if sample_id_all {
                payload.extend_from_slice(&11_u32.to_le_bytes());
                payload.extend_from_slice(&12_u32.to_le_bytes());
                payload.extend_from_slice(&time.to_le_bytes());
            }
            records.push(record_bytes(3, &payload));
            let mut sample = sample_payload_with_optional_timestamp(
                sample_payload_with_period(0x2000, 11, 12, period, [0x2000]),
                true,
            );
            put_u64(&mut sample, 16, time);
            records.push(record_bytes_with_misc(
                PERF_RECORD_SAMPLE,
                PERF_RECORD_MISC_CPUMODE_USER,
                &sample,
            ));
        }
        let bytes = perfdata_with_records_and_attrs_vec(
            vec![file_attr_bytes_with_flags(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_TIME
                    | PERF_SAMPLE_PERIOD
                    | PERF_SAMPLE_CALLCHAIN,
                if sample_id_all { 1 << 18 } else { 0 },
            )],
            records,
        );
        let (script, expected) = native_script_and_fold(&bytes);
        let options = FoldOptions {
            count_periods: true,
            inline: false,
        };
        let actual = fold_perfdata_callchains_with_options(&bytes, options).expect("fold");
        assert_eq!(actual, expected, "comm={name:?}; native script={script}");
        let root = tempfile::tempdir().expect("tempdir");
        let input = root.path().join("perf.data");
        std::fs::write(&input, bytes).expect("write fixture");
        assert_eq!(
            fold_perfdata_file_with_options(&input, options).expect("fold file"),
            expected,
            "comm={name:?}; native script={script}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn timed_sample_ip_with_a_newline_dso_preserves_inferno_state_across_samples() {
    use inferno::collapse::Collapse as _;
    // Inferno process_single_stack doesn't reset in_event at sample boundaries;
    // map.c:map__fprintf_dsoname writes newlines in DSO paths verbatim.
    let mut records = Vec::new();
    for (kind, mut payload) in [
        (3, comm_payload(11, 12, "worker")),
        (
            1,
            mmap_payload(
                11,
                12,
                0x1000,
                0x100,
                0,
                "/tmp/a\nworker 12 1.000000: 2 cycles",
            ),
        ),
        (1, mmap_payload(11, 12, 0x2000, 0x100, 0, "/tmp/normal")),
    ] {
        payload.resize(payload.len().next_multiple_of(8), 0);
        records.push(record_bytes_with_misc(
            kind,
            PERF_RECORD_MISC_CPUMODE_USER,
            &payload,
        ));
    }
    for ip in [0x1010, 0x2010] {
        records.push(record_bytes_with_misc(
            PERF_RECORD_SAMPLE,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_optional_timestamp(
                sample_payload_with_period_no_callchain(ip, 11, 12, 5),
                true,
            ),
        ));
    }
    let mut bytes = perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_PERIOD,
            0,
            0,
        )],
        records,
    );
    put_u64(&mut bytes, 16, 144);
    let root = tempfile::tempdir().expect("tempdir");
    let input = root.path().join("perf.data");
    std::fs::write(&input, &bytes).expect("write fixture");
    let perf = Command::new("perf")
        .args(["script", "--force", "-i"])
        .arg(&input)
        .output()
        .expect("perf script");
    assert!(
        perf.status.success(),
        "{}",
        String::from_utf8_lossy(&perf.stderr)
    );
    let mut native = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(std::io::Cursor::new(&perf.stdout), &mut native)
        .expect("Inferno");
    let actual = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("fold");
    assert_eq!(
        actual.as_bytes(),
        native,
        "native script={}",
        String::from_utf8_lossy(&perf.stdout)
    );
    assert!(native.is_empty());
    let file_backed = fold_perfdata_file_with_options(
        &input,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("fold file");
    assert_eq!(file_backed, actual);
}

#[test]
fn untimed_sample_ip_headers_without_callchains_form_one_inferno_stack() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD,
            0,
            0,
        )],
        [
            record_bytes(
                9,
                &sample_payload_with_period_no_callchain(0x2000, 11, 12, 7),
            ),
            record_bytes(
                9,
                &sample_payload_with_period_no_callchain(0x2000, 11, 12, 3),
            ),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(
        folded,
        ":12;12          3 cycles:              2000 [unknown] 1\n"
    );
}

#[test]
fn sample_ip_kernel_cpumode_folds_only_with_a_timestamp_like_native_pipeline() {
    // perf builtin-script.c process_sample_event() resolves the event-line IP
    // with machine__resolve(), and util/event.c machine__resolve() passes
    // sample->cpumode into thread__find_map(). This is not the recorded
    // callchain path, whose util/machine.c thread__resolve_callchain_sample()
    // starts in PERF_RECORD_MISC_USER and switches only on PERF_CONTEXT_*.
    for timed in [false, true] {
        let bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_PERIOD
                    | if timed { PERF_SAMPLE_TIME } else { 0 },
                0,
                0,
            )],
            [
                record_bytes_with_misc(
                    1,
                    PERF_RECORD_MISC_CPUMODE_KERNEL,
                    &mmap_payload(
                        u32::MAX,
                        u32::MAX,
                        0xffff_ffff_8800_0000,
                        0x2000,
                        0,
                        "[kernel.kallsyms]",
                    ),
                ),
                record_bytes_with_misc(
                    9,
                    PERF_RECORD_MISC_CPUMODE_KERNEL,
                    &sample_payload_with_optional_timestamp(
                        sample_payload_with_period_no_callchain(0xffff_ffff_8800_0010, 11, 12, 7),
                        timed,
                    ),
                ),
            ],
        );
        let resolver = StaticSymbolResolver;

        let folded = fold_perfdata_callchains_with_symbols(
            &bytes,
            FoldOptions {
                count_periods: true,
                inline: false,
            },
            &resolver,
        )
        .expect("folded");

        assert_eq!(
            folded,
            if timed {
                ":12;asm_exc_page_fault 7\n"
            } else {
                ""
            }
        );
    }
}

#[test]
fn sample_ip_with_dwarf_payload_but_no_callchain_folds_only_with_a_timestamp() {
    for timed in [false, true] {
        let bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes_with_regs(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_PERIOD
                    | PERF_SAMPLE_REGS_USER
                    | PERF_SAMPLE_STACK_USER
                    | if timed { PERF_SAMPLE_TIME } else { 0 },
                (1 << 6) | (1 << 7) | (1 << 8),
            )],
            [record_bytes(
                9,
                &sample_payload_with_optional_timestamp(
                    sample_payload_with_period_and_user_stack_no_callchain(
                        0x4000,
                        11,
                        12,
                        7,
                        1,
                        [0x7fff_0008, 0x7fff_0000, 0x4000],
                        [
                            0, 0, 0, 0, 0, 0, 0, 0, //
                            0x40, 0, 0, 0, 0, 0, 0, 0, //
                            0x34, 0x12, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    timed,
                ),
            )],
        );

        let folded = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions {
                count_periods: true,
                inline: false,
            },
        )
        .expect("folded");

        assert_eq!(folded, if timed { ":12;[unknown] 7\n" } else { "" });
    }
}

#[test]
fn sample_ip_uses_base_symbol_with_inline_enabled_but_needs_time_for_inferno() {
    // builtin-script.c process_event() only resolves a callchain cursor when
    // sample->callchain exists. Without PERF_SAMPLE_CALLCHAIN, the event-line
    // IP is printed through machine__resolve()/map__find_symbol(), even if
    // inline output is otherwise enabled.
    for timed in [false, true] {
        let bytes = perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_PERIOD
                    | if timed { PERF_SAMPLE_TIME } else { 0 },
                0,
                0,
            )],
            [
                record_bytes(1, &mmap_payload(11, 12, 0x1000, 0x100, 0, "/bin/app")),
                record_bytes(
                    9,
                    &sample_payload_with_optional_timestamp(
                        sample_payload_with_period_no_callchain(0x1010, 11, 12, 7),
                        timed,
                    ),
                ),
            ],
        );
        let resolver = SampleIpInlineSymbolResolver;

        let folded = fold_perfdata_callchains_with_symbols(
            &bytes,
            FoldOptions {
                count_periods: true,
                inline: true,
            },
            &resolver,
        )
        .expect("folded");

        assert_eq!(folded, if timed { ":12;app::main 7\n" } else { "" });
    }
}

#[test]
fn selects_untimed_sample_layout_by_identifier_without_using_period_as_weight() {
    let attr1 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
        392,
        [111],
    );
    let attr2 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        400,
        [222],
    );
    let bytes = perfdata_with_attrs_ids_and_records(
        [attr1, attr2],
        [111, 222],
        [record_bytes(
            9,
            &sample_payload_with_identifier_and_period(222, 0x1000, 11, 12, 7, [0x2000]),
        )],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn selects_untimed_sample_layout_by_id_without_using_period_as_weight() {
    let attr1 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ID | PERF_SAMPLE_CALLCHAIN,
        392,
        [111],
    );
    let attr2 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_ID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        400,
        [222],
    );
    let bytes = perfdata_with_attrs_ids_and_records(
        [attr1, attr2],
        [111, 222],
        [record_bytes(
            9,
            &sample_payload_with_id_and_period(0x1000, 11, 12, 222, 7, [0x2000]),
        )],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn folds_untimed_samples_from_multiple_attrs_with_infernos_empty_event_filter() {
    let attr1 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        392,
        [111],
    );
    let attr2 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        400,
        [222],
    );
    let bytes = perfdata_with_attrs_ids_and_records(
        [attr1, attr2],
        [111, 222],
        [
            record_bytes(
                9,
                &sample_payload_with_identifier_and_period(222, 0x1000, 11, 12, 2, [0x2222]),
            ),
            record_bytes(
                9,
                &sample_payload_with_identifier_and_period(111, 0x1000, 11, 12, 1, [0x1111]),
            ),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 2\n");
}

#[test]
fn folds_untimed_perfdata_from_file_with_infernos_unit_weights() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 3, [0x2000])),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded = fold_perfdata_file_with_options(
        &perfdata,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 2\n");
}

#[test]
fn file_path_folding_without_sample_id_all_does_not_apply_future_mmaps_to_samples() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let mut records = Vec::new();
    for _ in 0..10_000 {
        records.push(record_bytes(
            9,
            &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000]),
        ));
    }
    records.push(record_bytes(
        1,
        &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app"),
    ));
    let bytes = perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        records,
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("folded");

    assert_eq!(folded, ":12;[unknown] 10000\n");
}

#[test]
fn file_path_folding_without_sample_id_all_keeps_input_order_across_finished_rounds() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app")),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn file_backed_folding_matches_in_memory_folding_across_finished_rounds() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 40, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, &bytes).expect("write perfdata");

    let in_memory =
        fold_perfdata_callchains_with_options(&bytes, FoldOptions::default()).expect("in memory");
    let file_backed =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("file backed");

    assert_eq!(file_backed, in_memory);
}

#[test]
fn folds_untimed_perfdata_across_finished_rounds_with_infernos_unit_weights() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 3, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded = fold_perfdata_file_with_options(
        &perfdata,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 2\n");
}

#[test]
fn folds_later_rounds_with_updated_mappings_after_cacheable_rounds() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 1, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 1, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("folded");

    assert_eq!(folded, ":12;[app] 1\n:12;[unknown] 1\n");
}

#[test]
fn folds_identical_untimed_stacks_across_pids_using_unit_weights() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 12, "pyroclast")),
            record_bytes(3, &comm_payload(21, 22, "pyroclast")),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(9, &sample_payload_with_period(0x1000, 21, 22, 3, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, "pyroclast;[unknown] 2\n");
}

#[test]
fn forked_process_inherits_parent_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app")),
            record_bytes(PERF_RECORD_FORK, &fork_payload(22, 11, 22, 11, 99)),
            record_bytes(9, &sample_payload_with_period(0x1000, 22, 22, 7, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":22;[app] 1\n");
}

#[test]
fn synthesized_fork_does_not_clone_parent_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app")),
            record_bytes_with_misc(
                PERF_RECORD_FORK,
                PERF_RECORD_MISC_COMM_EXEC,
                &fork_payload(22, 11, 22, 11, 99),
            ),
            record_bytes(9, &sample_payload_with_period(0x1000, 22, 22, 7, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":22;[unknown] 1\n");
}

#[test]
fn applies_comm_records_by_perf_timestamp_from_file_path_like_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            record_bytes(
                3,
                &comm_payload_with_sample_id_time(11, 12, "perf-exec", 10),
            ),
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload_with_sample_id_time(11, 11, "pyroclast", 20),
            ),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("folded");

    assert_eq!(folded, "perf-exec;[unknown] 1\n");
}

#[test]
fn file_and_slice_replay_apply_timestamp_order_across_distant_input_ranges() {
    let mut records = vec![
        record_bytes(3, &comm_payload_with_sample_id_time(11, 12, "before", 10)),
        record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
    ];
    let padding = record_bytes(100, &vec![0; 65520]);
    records.extend(std::iter::repeat_n(padding.clone(), 160));
    records.extend([
        record_bytes(3, &comm_payload_with_sample_id_time(11, 12, "after", 20)),
        record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 15, [0x2000])),
    ]);
    records.extend(std::iter::repeat_n(padding, 80));
    records.push(record_bytes(PERF_RECORD_FINISHED_ROUND, b""));
    let bytes = perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        records,
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    let options = FoldOptions::default();
    let memory = fold_perfdata_callchains_with_options(&bytes, options).unwrap();
    let disk = fold_perfdata_file_with_options(file.path(), options).unwrap();
    assert_eq!(memory, "after;[unknown] 1\nbefore;[unknown] 1\n");
    assert_eq!(disk, memory);
}

#[test]
fn folds_file_samples_from_multiple_attrs_when_generated_perf_script_event_name_matches_inferno_filter()
 {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let attr1 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        392,
        [111],
    );
    let attr2 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        400,
        [222],
    );
    let bytes = perfdata_with_attrs_ids_and_records(
        [attr1, attr2],
        [111, 222],
        [
            record_bytes(
                9,
                &sample_payload_with_identifier_time_and_period(
                    222,
                    0x1000,
                    11,
                    12,
                    30,
                    2,
                    [0x2222],
                ),
            ),
            record_bytes(
                9,
                &sample_payload_with_identifier_time_and_period(
                    111,
                    0x1000,
                    11,
                    12,
                    20,
                    1,
                    [0x1111],
                ),
            ),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded = fold_perfdata_file_with_options(
        &perfdata,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 3\n");
}

proptest! {
    #[test]
    fn property_summarizes_generated_lost_record_totals(
        entries in prop::collection::vec((any::<bool>(), any::<u64>()), 0..32),
    ) {
        let records = entries
            .iter()
            .enumerate()
            .map(|(index, (is_lost_samples, lost))| {
                if *is_lost_samples {
                    record_bytes(13, &lost.to_le_bytes())
                } else {
                    record_bytes(2, &lost_payload(index as u64, *lost))
                }
            })
            .collect::<Vec<_>>();
        let bytes = perfdata_with_records_and_attrs_vec(Vec::new(), records);

        let summary = summarize_perfdata(&bytes).expect("summary");
        let expected_lost = entries
            .iter()
            .fold(0_u64, |total, (_, lost)| total.saturating_add(*lost));
        let expected_lost_records = entries.iter().filter(|(is_lost_samples, _)| !is_lost_samples).count();
        let expected_lost_samples = entries.iter().filter(|(is_lost_samples, _)| *is_lost_samples).count();

        prop_assert_eq!(summary.total_records, entries.len());
        prop_assert_eq!(summary.record_count(2), expected_lost_records);
        prop_assert_eq!(summary.record_count(13), expected_lost_samples);
        prop_assert_eq!(summary.lost_records, expected_lost);
    }

    #[test]
    fn property_untimed_callchains_use_unit_weights_for_arbitrary_periods(
        frames in prop::collection::vec(0x1000_u64..0x0001_0000_0000_u64, 1..12),
        periods in prop::collection::vec(1_u64..10_000, 1..16),
    ) {
        let records = periods
            .iter()
            .map(|period| {
                record_bytes(
                    9,
                    &sample_payload_with_period_vec(0x1000, 11, 12, *period, &frames),
                )
            })
            .collect::<Vec<_>>();
        let bytes = perfdata_with_records_and_attrs_vec(
            vec![file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            records,
        );

        let folded = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions { count_periods: true, inline: false },
        )
        .expect("folded");
        let expected = render_unknown_folded_callchain(&frames, periods.len() as u64);

        prop_assert_eq!(folded, expected);
    }

    #[test]
    fn property_selects_untimed_identifier_layout_with_unit_weight(
        base_id in 1_u64..u64::MAX,
        period in 1_u64..10_000,
        frame in 0x1000_u64..0x0001_0000_0000_u64,
    ) {
        let attr1 = file_attr_bytes_with_ids(
            PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            392,
            [base_id],
        );
        let attr2 = file_attr_bytes_with_ids(
            PERF_SAMPLE_IDENTIFIER
                | PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            400,
            [base_id + 1],
        );
        let bytes = perfdata_with_attrs_ids_and_records(
            [attr1, attr2],
            [base_id, base_id + 1],
            [record_bytes(
                9,
                &sample_payload_with_identifier_and_period_vec(base_id + 1, 0x1000, 11, 12, period, &[frame]),
            )],
        );

        let folded = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions { count_periods: true, inline: false },
        )
        .expect("folded");

        prop_assert_eq!(folded, render_unknown_folded_callchain(&[frame], 1));
    }

    #[test]
    fn property_selects_untimed_id_layout_with_unit_weight(
        base_id in 1_u64..u64::MAX,
        period in 1_u64..10_000,
        frame in 0x1000_u64..0x0001_0000_0000_u64,
    ) {
        let attr1 = file_attr_bytes_with_ids(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ID | PERF_SAMPLE_CALLCHAIN,
            392,
            [base_id],
        );
        let attr2 = file_attr_bytes_with_ids(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_ID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            400,
            [base_id + 1],
        );
        let bytes = perfdata_with_attrs_ids_and_records(
            [attr1, attr2],
            [base_id, base_id + 1],
            [record_bytes(
                9,
                &sample_payload_with_id_and_period_vec(0x1000, 11, 12, base_id + 1, period, &[frame]),
            )],
        );

        let folded = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions { count_periods: true, inline: false },
        )
        .expect("folded");

        prop_assert_eq!(folded, render_unknown_folded_callchain(&[frame], 1));
    }
}

#[test]
fn folds_unsymbolized_mapped_user_frames_like_inferno_module_fallback() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[app] 1\n");
}

#[test]
fn folds_unsymbolized_bracket_mappings_like_inferno_module_fallback() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x7000, 0x100, 0, "[vdso]")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x7010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[[vdso]] 1\n");
}

#[test]
fn folds_mmap2_build_id_records_as_mappings() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                10,
                1 << 14,
                &mmap2_build_id_payload(11, 11, 0x4000, 0x100, 0x20, "/bin/build-id-app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[build-id-app] 1\n");
}

#[test]
fn symbolized_fold_carries_mmap2_build_ids_to_symbol_requests() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                10,
                1 << 14,
                &mmap2_build_id_payload(11, 11, 0x4000, 0x100, 0x20, "[igb]"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[[igb]] 1\n");
    assert_eq!(
        resolver.calls(),
        vec![vec![SymbolRequest {
            kernel_module_address: None,
            path: std::path::PathBuf::from("[igb]"),
            relative_address: 0x30,
            kernel_mapping_range: None,
            build_id: Some("aabbccdd".to_string()),
            file_identity: None,
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn module_only_fold_without_core_loading_does_not_resurrect_failed_build_id_module() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                10,
                PERF_RECORD_MISC_CPUMODE_KERNEL | PERF_RECORD_MISC_MMAP_BUILD_ID,
                &mmap2_build_id_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_c0ed_5900,
                    0x1000,
                    0,
                    "[zfs]",
                ),
            ),
            record_bytes(
                PERF_RECORD_SAMPLE,
                &sample_payload(
                    0xffff_ffff_c0ed_5ffa,
                    11,
                    12,
                    [0xffff_ffff_ffff_ff80, 0xffff_ffff_c0ed_5ffa],
                ),
            ),
        ],
    );
    let root = tempfile::tempdir().expect("root");
    let perfdata = root.path().join("perf.data");
    std::fs::write(&perfdata, &bytes).expect("perfdata");
    let live_kallsyms = root.path().join("kallsyms");
    std::fs::write(
        &live_kallsyms,
        "ffffffffc0ed5900 t arc_read [zfs]\nffffffffc0ed6100 t arc_read_next [zfs]\n",
    )
    .expect("kallsyms");
    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        RecordingSymbolResolver::default(),
        &perfdata,
        root.path(),
        [],
        &live_kallsyms,
    );

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    // perf symbol.c:dso__load marks the module loaded even on failure (1866);
    // ordinary kallsyms is loaded through the core DSO, not by a module query.
    // maps__split_kallsyms (913) skips this DSO if core is later loaded.
    assert_eq!(folded, ":12;[[zfs]] 1\n");
}

#[test]
fn symbolized_fold_carries_mmap2_file_identity_to_symbol_requests() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x4000, 0x100, 0x20, 5, "/bin/app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[app] 1\n");
    assert_eq!(
        resolver.calls(),
        vec![vec![SymbolRequest {
            kernel_module_address: None,
            path: std::path::PathBuf::from("/bin/app"),
            relative_address: 0x30,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: Some(FileIdentity {
                major: 8,
                minor: 1,
                inode: 99,
                inode_generation: 7,
            }),
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn symbolized_fold_carries_header_build_ids_to_mmap2_symbol_requests() {
    let build_id = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
        0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
    ];
    let bytes = perfdata_with_records_attrs_and_build_id_feature(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x4000, 0x100, 0x20, 5, "/tmp/stale-app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4010])),
        ],
        &build_id_event_payload(u32::MAX, &build_id, "/tmp/stale-app"),
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[stale-app] 1\n");
    assert_eq!(
        resolver.calls(),
        vec![vec![SymbolRequest {
            kernel_module_address: None,
            path: std::path::PathBuf::from("/tmp/stale-app"),
            relative_address: 0x30,
            kernel_mapping_range: None,
            build_id: Some("aabbccddeeff102030405060708090a0b0c0d0e0".to_string()),
            file_identity: Some(FileIdentity {
                major: 8,
                minor: 1,
                inode: 99,
                inode_generation: 7,
            }),
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn folds_mapped_user_frames_with_symbol_names() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1010])),
        ],
    );
    let resolver = StaticSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;app::main;app::main 1\n");
}

#[test]
fn symbolized_fold_expands_inline_symbol_frames_with_inline_option() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );
    let resolver = InlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(
        &bytes,
        FoldOptions {
            inline: true,
            ..FoldOptions::default()
        },
        &resolver,
    )
    .expect("folded");

    assert_eq!(folded, ":12;app::outer;app::inner 1\n");
}

#[test]
fn symbolized_fold_renders_inline_arrows_with_inline_option_like_inferno_collapse_perf() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );
    let resolver = ArrowInlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(
        &bytes,
        FoldOptions {
            inline: true,
            ..FoldOptions::default()
        },
        &resolver,
    )
    .expect("folded");

    assert_eq!(folded, ":12;app::outer;app::middle;app::inner_[i] 1\n");
}

#[test]
fn symbolized_fold_keeps_unknown_caller_before_inline_frames_with_inline_option_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "[unknown]")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x2010])),
        ],
    );
    let resolver = InlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(
        &bytes,
        FoldOptions {
            inline: true,
            ..FoldOptions::default()
        },
        &resolver,
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown];app::outer;app::inner 1\n");
}

#[test]
fn symbolized_fold_keeps_module_fallback_caller_before_inline_frames_with_inline_option_like_perf_script()
 {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x2000, 0x100, 0, 0, "/lib/libc.so.6"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x2010])),
        ],
    );
    let resolver = InlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(
        &bytes,
        FoldOptions {
            inline: true,
            ..FoldOptions::default()
        },
        &resolver,
    )
    .expect("folded");

    assert_eq!(folded, ":12;[libc.so.6];app::outer;app::inner 1\n");
}

#[test]
fn symbolized_fold_renders_unmapped_user_caller_before_inline_frames_with_inline_option_like_perf_script()
 {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x2010])),
        ],
    );
    let resolver = InlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(
        &bytes,
        FoldOptions {
            inline: true,
            ..FoldOptions::default()
        },
        &resolver,
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown];app::outer;app::inner 1\n");
}

#[test]
fn symbolized_fold_uses_module_fallback_for_unresolved_user_frames_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/usr/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[app] 1\n");
}

#[test]
fn symbolized_fold_drops_process_name_only_stacks_without_inventing_module_fallback() {
    // Inferno src/collapse/perf.rs:on_stack_line returns immediately when
    // rawfunc starts with '('. after_event emits only nonempty stacks. A
    // resolved-but-suppressed name is not an unresolved [unknown] symbol.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );
    let resolver = ProcessNameSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn leaves_kernel_space_frames_as_hex_without_symbol_lookup() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0xffff_ffff_8800_0000, 0x2000, 0, "/bin/app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;0xffffffff88000010 1\n");
    assert_eq!(resolver.calls(), Vec::<Vec<SymbolRequest>>::new());
}

#[test]
fn folds_unmapped_kernel_frames_as_unknown_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn kernel_looking_user_callchain_without_kernel_context_stays_unknown_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_8800_0000,
                    0x2000,
                    0,
                    "[kernel.kallsyms]",
                ),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn keeps_kernel_frames_from_mmap2_records_without_exec_prot() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                10,
                PERF_RECORD_MISC_CPUMODE_KERNEL,
                &mmap2_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_8800_0000,
                    0x2000,
                    0,
                    0,
                    "[kernel.kallsyms]",
                ),
            ),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0xffff_ffff_ffff_ff80, 0xffff_ffff_8800_0010],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[[kernel.kallsyms]] 1\n");
}

#[test]
fn symbolized_fold_uses_module_fallback_for_unresolved_kernel_frames_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                1,
                PERF_RECORD_MISC_CPUMODE_KERNEL,
                &mmap_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_8800_0000,
                    0x2000,
                    0,
                    "[kernel.kallsyms]_text",
                ),
            ),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0xffff_ffff_ffff_ff80, 0xffff_ffff_8800_0010],
                ),
            ),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[[kernel.kallsyms]] 1\n");
}

#[test]
fn symbolized_fold_resolves_mapped_kernel_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                1,
                PERF_RECORD_MISC_CPUMODE_KERNEL,
                &mmap_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_8800_0000,
                    0x2000,
                    0,
                    "[kernel.kallsyms]",
                ),
            ),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0xffff_ffff_ffff_ff80, 0xffff_ffff_8800_0010],
                ),
            ),
        ],
    );
    let resolver = StaticSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;asm_exc_page_fault 1\n");
}

#[test]
fn symbolized_fold_resolves_kernel_module_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                1,
                PERF_RECORD_MISC_CPUMODE_KERNEL,
                &mmap_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_c000_0000,
                    0x2000,
                    0,
                    "[zfs]",
                ),
            ),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0xffff_ffff_ffff_ff80, 0xffff_ffff_c000_0123],
                ),
            ),
        ],
    );
    let resolver = StaticSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;zfs_read 1\n");
}

#[test]
fn resolves_unique_addresses_once_per_delivered_sample() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1020])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1020])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;app::work;app::main 2\n");
    let mut calls = resolver.calls();
    assert_eq!(calls.len(), 1);
    let mut requests = calls.pop().expect("prefetch batch");
    requests.sort_by_key(|request| request.relative_address);
    assert_eq!(
        requests,
        vec![
            SymbolRequest {
                kernel_module_address: None,
                path: std::path::PathBuf::from("/bin/app"),
                relative_address: 0x10,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                kernel_module_address: None,
                path: std::path::PathBuf::from("/bin/app"),
                relative_address: 0x20,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }
        ]
    );
}

#[test]
fn resolves_samples_at_delivery_without_a_recording_sized_symbol_batch() {
    let mut records = vec![record_bytes(
        1,
        &mmap_payload(11, 11, 0x1000, 0x3000, 0, "/bin/app"),
    )];
    for index in 0..4097_u64 {
        records.push(record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0x1030 + index]),
        ));
    }
    let bytes = perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        records,
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[app] 4097\n");
    let calls = resolver.calls();
    assert_eq!(calls.len(), 4097);
    assert!(calls.iter().all(|batch| batch.len() == 1));
}

fn perfdata_with_records_and_attrs<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn perfdata_with_records_and_attrs_vec(attrs: Vec<[u8; 144]>, records: Vec<Vec<u8>>) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn perfdata_with_records_attrs_and_build_id_feature<const A: usize>(
    attrs: [[u8; 144]; A],
    records: impl AsRef<[Vec<u8>]>,
    build_id_payload: &[u8],
) -> Vec<u8> {
    let records = records.as_ref();
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let feature_table_offset = data_offset + data_size;
    let build_id_payload_offset = feature_table_offset + 16;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    // HEADER_BUILD_ID feature bit (2) in the adds_features bitmap, which struct
    // perf_file_header (tools/perf/util/header.h) places at byte offset 72.
    put_u64(&mut bytes, 72, 1 << 2);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes.resize(build_id_payload_offset, 0);
    put_u64(
        &mut bytes,
        feature_table_offset,
        build_id_payload_offset as u64,
    );
    put_u64(
        &mut bytes,
        feature_table_offset + 8,
        u64::try_from(build_id_payload.len()).expect("payload size"),
    );
    bytes.extend(build_id_payload);
    bytes
}

/// Builds a perf.data carrying a single `HEADER_ARCH` feature string (the
/// recording machine's `uname -m`). perf stores it as a `perf_header_string`:
/// a u32 length followed by that many NUL-terminated bytes (util/header.c
/// `write_arch/do_write_string`).
fn perfdata_with_records_attrs_and_arch_feature<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
    arch: &str,
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let feature_table_offset = data_offset + data_size;
    let arch_payload_offset = feature_table_offset + 16;
    // do_write_string aligns the length to NAME_ALIGN (64) and writes the
    // NUL-terminated name plus zero padding.
    let aligned = (arch.len() + 1).next_multiple_of(64);
    let mut arch_payload = Vec::new();
    arch_payload.extend(u32::try_from(aligned).expect("arch len").to_le_bytes());
    let mut name_bytes = arch.as_bytes().to_vec();
    name_bytes.resize(aligned, 0);
    arch_payload.extend(name_bytes);

    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    // HEADER_ARCH feature bit (6) in the adds_features bitmap, which struct
    // perf_file_header (tools/perf/util/header.h) places at byte offset 72.
    put_u64(&mut bytes, 72, 1 << 6);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes.resize(arch_payload_offset, 0);
    put_u64(&mut bytes, feature_table_offset, arch_payload_offset as u64);
    put_u64(
        &mut bytes,
        feature_table_offset + 8,
        u64::try_from(arch_payload.len()).expect("payload size"),
    );
    bytes.extend(arch_payload);
    bytes
}

fn perfdata_with_attrs_ids_and_records<const A: usize, const I: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    ids: [u64; I],
    records: [Vec<u8>; R],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let ids_size = ids.len() * 8;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size + ids_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for id in ids {
        bytes.extend(id.to_le_bytes());
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn file_attr_bytes(sample_type: u64, ids_offset: u64, ids_size: u64) -> [u8; 144] {
    let mut bytes = [0; 144];
    put_u32(&mut bytes, 4, 128);
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, 128, ids_offset);
    put_u64(&mut bytes, 136, ids_size);
    bytes
}

fn file_attr_bytes_with_flags(sample_type: u64, flags: u64) -> [u8; 144] {
    let mut bytes = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut bytes, 40, flags);
    bytes
}

fn file_attr_bytes_with_regs(sample_type: u64, sample_regs_user: u64) -> [u8; 144] {
    let mut bytes = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut bytes, 80, sample_regs_user);
    bytes
}

fn file_attr_bytes_with_ids<const N: usize>(
    sample_type: u64,
    ids_offset: u64,
    ids: [u64; N],
) -> [u8; 144] {
    file_attr_bytes(sample_type, ids_offset, (ids.len() * 8) as u64)
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    record_bytes_with_misc(record_type, 0, payload)
}

fn record_bytes_with_misc(record_type: u32, misc: u16, payload: &[u8]) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(record_type.to_le_bytes());
    bytes.extend(misc.to_le_bytes());
    bytes.extend(
        u16::try_from(size)
            .expect("record fits in u16")
            .to_le_bytes(),
    );
    bytes.extend(payload);
    bytes
}

fn callchain_deferred_payload<const N: usize>(cookie: u64, ips: [u64; N]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(cookie.to_le_bytes());
    payload.extend((ips.len() as u64).to_le_bytes());
    for ip in ips {
        payload.extend(ip.to_le_bytes());
    }
    payload
}

fn sample_payload<const N: usize>(ip: u64, pid: u32, tid: u32, callchain: [u64; N]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_time(
    ip: u64,
    pid: u32,
    tid: u32,
    time: u64,
    callchain: impl AsRef<[u64]>,
) -> Vec<u8> {
    let callchain = callchain.as_ref();
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_optional_timestamp(mut payload: Vec<u8>, timed: bool) -> Vec<u8> {
    if timed {
        payload.splice(16..16, 1_000_000_000_u64.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period_no_callchain(ip: u64, pid: u32, tid: u32, period: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload
}

fn sample_payload_with_period_and_user_stack_no_callchain<const R: usize, const S: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    abi: u64,
    regs: [u64; R],
    stack: [u8; S],
) -> Vec<u8> {
    let mut payload = sample_payload_with_period_no_callchain(ip, pid, tid, period);
    append_user_stack_payload(&mut payload, abi, regs, stack, S as u64);
    payload
}

fn sample_payload_with_identifier_and_period<const N: usize>(
    identifier: u64,
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(identifier.to_le_bytes());
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_identifier_time_and_period<const N: usize>(
    identifier: u64,
    ip: u64,
    pid: u32,
    tid: u32,
    time: u64,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(identifier.to_le_bytes());
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_id_and_period<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    id: u64,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(id.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period_vec(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: &[u64],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_identifier_and_period_vec(
    identifier: u64,
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: &[u64],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(identifier.to_le_bytes());
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_id_and_period_vec(
    ip: u64,
    pid: u32,
    tid: u32,
    id: u64,
    period: u64,
    callchain: &[u64],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(id.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_user_stack<const C: usize, const R: usize, const S: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    callchain: [u64; C],
    abi: u64,
    regs: [u64; R],
    stack: [u8; S],
) -> Vec<u8> {
    let mut payload = sample_payload(ip, pid, tid, callchain);
    append_user_stack_payload(&mut payload, abi, regs, stack, S as u64);
    payload
}

fn sample_payload_with_zero_dynamic_user_stack<const C: usize, const R: usize, const S: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    callchain: [u64; C],
    abi: u64,
    regs: [u64; R],
    stack: [u8; S],
) -> Vec<u8> {
    let mut payload = sample_payload(ip, pid, tid, callchain);
    append_user_stack_payload(&mut payload, abi, regs, stack, 0);
    payload
}

fn append_user_stack_payload<const R: usize, const S: usize>(
    payload: &mut Vec<u8>,
    abi: u64,
    regs: [u64; R],
    stack: [u8; S],
    dynamic_size: u64,
) {
    payload.extend(abi.to_le_bytes());
    for reg in regs {
        payload.extend(reg.to_le_bytes());
    }
    payload.extend((stack.len() as u64).to_le_bytes());
    payload.extend(stack);
    payload.extend(vec![0; stack.len().next_multiple_of(8) - stack.len()]);
    payload.extend(dynamic_size.to_le_bytes());
}

#[cfg(target_os = "linux")]
fn process_libc_path() -> Option<std::path::PathBuf> {
    std::fs::read_to_string("/proc/self/maps")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let _range = fields.next()?;
            let perms = fields.next()?;
            let _offset = fields.next()?;
            let _dev = fields.next()?;
            let _inode = fields.next()?;
            let path = fields.next()?;
            (perms.contains('x') && path.contains("libc.so.6"))
                .then(|| std::path::PathBuf::from(path))
        })
}

fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
    payload
}

fn comm_payload_with_sample_id_time(pid: u32, tid: u32, comm: &str, time: u64) -> Vec<u8> {
    let mut payload = comm_payload(pid, tid, comm);
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload
}

#[allow(clippy::similar_names)]
fn fork_payload(
    child_pid: u32,
    parent_pid: u32,
    child_tid: u32,
    parent_tid: u32,
    time: u64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(child_pid.to_le_bytes());
    payload.extend(parent_pid.to_le_bytes());
    payload.extend(child_tid.to_le_bytes());
    payload.extend(parent_tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload
}

fn mmap_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn mmap2_payload(
    pid: u32,
    tid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
    prot: u32,
    path: &str,
) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.extend(8u32.to_le_bytes());
    payload.extend(1u32.to_le_bytes());
    payload.extend(99u64.to_le_bytes());
    payload.extend(7u64.to_le_bytes());
    payload.extend(prot.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn mmap2_build_id_payload(
    pid: u32,
    tid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
    path: &str,
) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.push(4);
    payload.push(0);
    payload.extend(0u16.to_le_bytes());
    payload.extend([0xaa, 0xbb, 0xcc, 0xdd]);
    payload.extend([0; 16]);
    payload.extend(5u32.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn build_id_event_payload(pid: u32, build_id: &[u8; 20], filename: &str) -> Vec<u8> {
    let size = 36 + filename.len() + 1;
    let mut payload = Vec::new();
    payload.extend(67_u32.to_le_bytes());
    payload.extend(PERF_RECORD_MISC_CPUMODE_USER.to_le_bytes());
    payload.extend(u16::try_from(size).expect("event size").to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(build_id);
    payload.extend([0; 4]);
    payload.extend(filename.as_bytes());
    payload.push(0);
    payload
}

fn lost_payload(id: u64, lost: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(id.to_le_bytes());
    payload.extend(lost.to_le_bytes());
    payload
}

fn mmap_range_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(start.to_le_bytes());
    payload.extend(len.to_le_bytes());
    payload.extend(pgoff.to_le_bytes());
    payload
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

struct StaticSymbolResolver;

impl SymbolResolver for StaticSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                (request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10)
                    .then(|| "app::main".to_string())
                    .or_else(|| {
                        (request.path == std::path::Path::new("/bin/app")
                            && request.relative_address == 0x20)
                            .then(|| "app::work".to_string())
                    })
                    .or_else(|| {
                        (request.path == std::path::Path::new("[kernel.kallsyms]")
                            && request.relative_address == 0xffff_ffff_8800_0010)
                            .then(|| "asm_exc_page_fault".to_string())
                    })
                    .or_else(|| {
                        (request.path == std::path::Path::new("[zfs]")
                            && request.relative_address == 0xffff_ffff_c000_0123)
                            .then(|| "zfs_read".to_string())
                    })
            })
            .collect())
    }
}

struct InlineSymbolResolver;

impl SymbolResolver for InlineSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; requests.len()])
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                if request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10
                {
                    vec!["app::outer".to_string(), "app::inner".to_string()]
                } else {
                    Vec::new()
                }
            })
            .collect())
    }
}

struct SampleIpInlineSymbolResolver;

impl SymbolResolver for SampleIpInlineSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; requests.len()])
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                if request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10
                {
                    vec!["app::outer".to_string(), "app::inner".to_string()]
                } else {
                    Vec::new()
                }
            })
            .collect())
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                if request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10
                {
                    ResolvedSymbolFrames {
                        frames: vec!["app::main".to_string()],
                        source_state: pyroclast::symbols::SymbolSourceState::AddressDependent,
                        kernel_dso: pyroclast::symbols::SymbolDsoName::Mapping,
                        has_base_symbol: true,
                        has_inline_frames: false,
                        has_non_inline_base_frame: true,
                        base_offset: None,
                    }
                } else {
                    ResolvedSymbolFrames::default()
                }
            })
            .collect())
    }
}

struct ArrowInlineSymbolResolver;

struct SyntheticX86_64Object {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl SyntheticX86_64Object {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn create_compiled_startup() -> (Self, u64) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("startup.c");
        let path = dir.path().join("startup");
        std::fs::write(&source, "int main(void) { return 0; }\n").unwrap();
        let output = Command::new("cc")
            .args(["-g", "-O2", "-fPIE", "-pie"])
            .arg(&source)
            .arg("-o")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(&path).unwrap();
        let elf = object::File::parse(bytes.as_slice()).unwrap();
        let entry = elf
            .symbols()
            .find(|symbol| symbol.name() == Ok("_start"))
            .unwrap()
            .address();
        (Self { _dir: dir, path }, entry)
    }

    #[cfg(target_os = "linux")]
    fn create_with_stack_cfi() -> Self {
        let fixture = Self::create();
        let mut bytes = std::fs::read(&fixture.path).unwrap();
        // DW_CFA_def_cfa RSP+8, DW_CFA_offset RIP=[CFA-8]. The existing
        // FDE covers [0x100, 0x104), so captured words unwind mapped callers
        // independently of RBP (elfutils libdwfl/frame_unwind.c CFI path).
        bytes[0x111..0x118].copy_from_slice(&[0x0c, 7, 8, 0x90, 1, 0, 0]);
        std::fs::write(&fixture.path, bytes).unwrap();
        fixture
    }

    /// Minimal `x86_64` ELF with one `PT_LOAD` covering [0, 0x10000) and a
    /// nops-only FDE covering [0x100, 0x104). Fixed ELF bytes keep CFI and RBP
    /// fallback behavior independent of the host test binary's architecture
    /// and unwind sections. Tests outside that FDE exercise native fallback;
    /// tests inside it exercise the x86 ABI's initial CFI register rules.
    fn create() -> Self {
        let mut bytes = vec![0_u8; 0x240];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // EM_X86_64
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes()); // e_version
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
        bytes[40..48].copy_from_slice(&0x180_u64.to_le_bytes()); // e_shoff
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&3_u16.to_le_bytes()); // e_shnum
        bytes[62..64].copy_from_slice(&2_u16.to_le_bytes()); // e_shstrndx
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X
        bytes[96..104].copy_from_slice(&0x200_u64.to_le_bytes()); // p_filesz
        bytes[104..112].copy_from_slice(&0x1_0000_u64.to_le_bytes()); // p_memsz
        bytes[112..120].copy_from_slice(&0x1000_u64.to_le_bytes()); // p_align
        // .eh_frame at vaddr/offset 0x100: one CIE and one FDE covering only
        // [0x100, 0x104). Outside that range libdw uses the architecture
        // fallback; inside it the nops preserve its initial ABI CFI rules.
        let eh_frame: [u8; 52] = [
            0x14, 0, 0, 0, // CIE length
            0, 0, 0, 0, // CIE id
            0x01, b'z', b'R', 0, // version, augmentation "zR"
            0x01, 0x78, 0x10, // code align 1, data align -8, ra 16
            0x01, 0x1b, // augmentation: FDE encoding pcrel|sdata4
            0, 0, 0, 0, 0, 0, 0, // DW_CFA_nop padding
            0x14, 0, 0, 0, // FDE length
            0x1c, 0, 0, 0, // CIE pointer (back 28 bytes)
            0xe0, 0xff, 0xff, 0xff, // pc_begin: pcrel -0x20 -> vaddr 0x100
            0x04, 0, 0, 0, // pc_range 4
            0, // augmentation data length
            0, 0, 0, 0, 0, 0, 0, // DW_CFA_nop padding
            0, 0, 0, 0, // terminator
        ];
        bytes[0x100..0x100 + eh_frame.len()].copy_from_slice(&eh_frame);
        let strtab = b"\0.eh_frame\0.shstrtab\0";
        bytes[0x140..0x140 + strtab.len()].copy_from_slice(strtab);
        // Section headers: [0] SHT_NULL, [1] .eh_frame, [2] .shstrtab.
        let mut section =
            |index: usize, name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64| {
                let base = 0x180 + index * 64;
                bytes[base..base + 4].copy_from_slice(&name.to_le_bytes());
                bytes[base + 4..base + 8].copy_from_slice(&kind.to_le_bytes());
                bytes[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
                bytes[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
                bytes[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
                bytes[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
                bytes[base + 48..base + 56].copy_from_slice(&8_u64.to_le_bytes());
            };
        section(1, 1, 1, 2, 0x100, 0x100, 52); // .eh_frame PROGBITS ALLOC
        section(2, 11, 3, 0, 0, 0x140, 21); // .shstrtab STRTAB
        let dir = tempfile::tempdir().expect("fixture dir");
        let path = dir.path().join("fixture-x86-64");
        std::fs::write(&path, &bytes).expect("write fixture elf");
        Self { _dir: dir, path }
    }

    fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    fn file_name(&self) -> &str {
        self.path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture file name")
    }
}

/// Minimal aarch64 ELF, structurally identical to `SyntheticX86_64Object` but
/// with `e_machine = EM_AARCH64` (183) and a `.eh_frame` FDE that covers only
/// `[0x100, 0x104)`. Used to pin the aarch64 scenario-D leaf-only case: a
/// reported module, no FDE covering the sampled pc, and `lr == 0` so the
/// elfutils `backends/aarch64_unwind.c` fallback fails before producing any
/// caller.
struct SyntheticAarch64Object {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl SyntheticAarch64Object {
    #[cfg(target_os = "linux")]
    fn create_with_symbol() -> Self {
        // Perf thread.c:519-547 discovers e_machine through loaded DSOs.
        // A symbol-less ELF is NOT_FOUND (dso.c:1323), falling back to the
        // host architecture rather than HEADER_ARCH. Give it a real text symbol.
        let fixture = Self::create();
        let mut bytes = std::fs::read(&fixture.path).unwrap();
        bytes.resize(0x4004, 0);
        bytes.copy_within(0x180..0x240, 0x280);
        put_u64(&mut bytes, 40, 0x280);
        bytes[60..62].copy_from_slice(&6_u16.to_le_bytes());
        put_u64(&mut bytes, 96, 0x4004);
        let names = b"\0.eh_frame\0.shstrtab\0.symtab\0.strtab\0.text\0";
        bytes[0x140..0x140 + names.len()].copy_from_slice(names);
        put_u64(&mut bytes, 0x300 + 32, names.len() as u64);
        bytes[0x180..0x1b0].fill(0);
        put_u32(&mut bytes, 0x198, 1);
        bytes[0x19c] = 0x12; // STB_GLOBAL | STT_FUNC
        bytes[0x19e..0x1a0].copy_from_slice(&5_u16.to_le_bytes());
        put_u64(&mut bytes, 0x1a0, 0x4000);
        put_u64(&mut bytes, 0x1a8, 4);
        bytes[0x1c0..0x1c6].copy_from_slice(b"\0seed\0");
        bytes[0x4000..0x4004].copy_from_slice(&[0x1f, 0x20, 0x03, 0xd5]); // nop
        for (index, name, kind, flags, addr, offset, size, align) in [
            (3, 21, 2, 0, 0, 0x180, 48, 8),
            (4, 29, 3, 0, 0, 0x1c0, 6, 1),
            (5, 37, 1, 6, 0x4000, 0x4000, 4, 4),
        ] {
            let base = 0x280 + index * 64;
            put_u32(&mut bytes, base, name);
            put_u32(&mut bytes, base + 4, kind);
            for (at, value) in [
                (8, flags),
                (16, addr),
                (24, offset),
                (32, size),
                (48, align),
            ] {
                put_u64(&mut bytes, base + at, value);
            }
        }
        put_u32(&mut bytes, 0x340 + 40, 4); // .symtab sh_link = .strtab
        put_u32(&mut bytes, 0x340 + 44, 1); // first global symbol
        put_u64(&mut bytes, 0x340 + 56, 24);
        std::fs::write(&fixture.path, bytes).unwrap();
        fixture
    }

    fn create() -> Self {
        let mut bytes = vec![0_u8; 0x240];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN
        bytes[18..20].copy_from_slice(&183_u16.to_le_bytes()); // EM_AARCH64
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes()); // e_version
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
        bytes[40..48].copy_from_slice(&0x180_u64.to_le_bytes()); // e_shoff
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&3_u16.to_le_bytes()); // e_shnum
        bytes[62..64].copy_from_slice(&2_u16.to_le_bytes()); // e_shstrndx
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X
        bytes[96..104].copy_from_slice(&0x200_u64.to_le_bytes()); // p_filesz
        bytes[104..112].copy_from_slice(&0x1_0000_u64.to_le_bytes()); // p_memsz
        bytes[112..120].copy_from_slice(&0x1000_u64.to_le_bytes()); // p_align
        let eh_frame: [u8; 52] = [
            0x14, 0, 0, 0, // CIE length
            0, 0, 0, 0, // CIE id
            0x01, b'z', b'R', 0, // version, augmentation "zR"
            0x01, 0x78, 0x1e, // code align 1, data align -8, ra 30 (aarch64 LR)
            0x01, 0x1b, // augmentation: FDE encoding pcrel|sdata4
            0, 0, 0, 0, 0, 0, 0, // DW_CFA_nop padding
            0x14, 0, 0, 0, // FDE length
            0x1c, 0, 0, 0, // CIE pointer (back 28 bytes)
            0xe0, 0xff, 0xff, 0xff, // pc_begin: pcrel -0x20 -> vaddr 0x100
            0x04, 0, 0, 0, // pc_range 4
            0, // augmentation data length
            0, 0, 0, 0, 0, 0, 0, // DW_CFA_nop padding
            0, 0, 0, 0, // terminator
        ];
        bytes[0x100..0x100 + eh_frame.len()].copy_from_slice(&eh_frame);
        let strtab = b"\0.eh_frame\0.shstrtab\0";
        bytes[0x140..0x140 + strtab.len()].copy_from_slice(strtab);
        let mut section =
            |index: usize, name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64| {
                let base = 0x180 + index * 64;
                bytes[base..base + 4].copy_from_slice(&name.to_le_bytes());
                bytes[base + 4..base + 8].copy_from_slice(&kind.to_le_bytes());
                bytes[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
                bytes[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
                bytes[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
                bytes[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
                bytes[base + 48..base + 56].copy_from_slice(&8_u64.to_le_bytes());
            };
        section(1, 1, 1, 2, 0x100, 0x100, 52); // .eh_frame PROGBITS ALLOC
        section(2, 11, 3, 0, 0, 0x140, 21); // .shstrtab STRTAB
        let dir = tempfile::tempdir().expect("fixture dir");
        let path = dir.path().join("fixture-aarch64");
        std::fs::write(&path, &bytes).expect("write fixture elf");
        Self { _dir: dir, path }
    }

    fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    fn file_name(&self) -> &str {
        self.path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture file name")
    }
}

fn current_exe_file_name() -> String {
    std::env::current_exe()
        .expect("current exe")
        .file_name()
        .expect("current exe file name")
        .to_string_lossy()
        .into_owned()
}

impl SymbolResolver for ArrowInlineSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; requests.len()])
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                if request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10
                {
                    vec![
                        "app::outer".to_string(),
                        "app::middle->app::inner".to_string(),
                    ]
                } else {
                    Vec::new()
                }
            })
            .collect())
    }
}

struct ProcessNameSymbolResolver;

impl SymbolResolver for ProcessNameSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                (request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10)
                    .then(|| "(python)".to_string())
            })
            .collect())
    }
}

#[derive(Default)]
struct RecordingSymbolResolver {
    calls: RefCell<Vec<Vec<SymbolRequest>>>,
}

impl RecordingSymbolResolver {
    fn calls(&self) -> Vec<Vec<SymbolRequest>> {
        self.calls.borrow().clone()
    }
}

impl SymbolResolver for RecordingSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.calls.borrow_mut().push(requests.to_vec());
        Ok(requests
            .iter()
            .map(|request| {
                (request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10)
                    .then(|| "app::main".to_string())
                    .or_else(|| {
                        (request.path == std::path::Path::new("/bin/app")
                            && request.relative_address == 0x20)
                            .then(|| "app::work".to_string())
                    })
            })
            .collect())
    }
}

#[cfg(target_os = "linux")]
#[test]
fn kcore_failed_cached_module_loading_preserves_first_cursor_then_replaces_maps() {
    let (root, _) = write_native_kcore_fixture("[a]");
    let debug = root.path().join(".debug");
    let object = pyroclast::symbols::perf_build_id_elf_path(&debug, "abcdef");
    std::fs::create_dir_all(object.parent().unwrap()).unwrap();
    std::fs::write(object, b"malformed ELF").unwrap();
    let module = SymbolRequest {
        kernel_module_address: None,
        path: "[a]".into(),
        relative_address: 0xffff_ffff_c100_0010,
        kernel_mapping_range: Some((0xffff_ffff_c100_0000, 0xffff_ffff_c100_4000)),
        build_id: Some("abcdef".into()),
        file_identity: None,
        kernel_relocation: None,
    };
    for scalar in [false, true] {
        let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            pyroclast::symbols::RustAddr2lineResolver::new(),
            &root.path().join("perf.data"),
            root.path(),
            [],
            &root.path().join("kallsyms"),
        );
        if scalar {
            assert_eq!(
                resolver
                    .resolve_batch(std::slice::from_ref(&module))
                    .unwrap(),
                [None]
            );
            assert_eq!(
                resolver
                    .resolve_batch(std::slice::from_ref(&module))
                    .unwrap(),
                [Some("first+0x10".into())]
            );
        } else {
            assert!(
                resolver
                    .resolve_frame_batch_with_metadata(std::slice::from_ref(&module))
                    .unwrap()[0]
                    .frames
                    .is_empty()
            );
            assert_eq!(
                resolver
                    .resolve_frame_batch_with_metadata(std::slice::from_ref(&module))
                    .unwrap()[0]
                    .frames,
                ["first+0x10"]
            );
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kcore_rejects_shared_module_with_a_separate_dynamic_map() {
    use inferno::collapse::Collapse as _;
    let (root, bytes) = write_native_cached_module_fixture(true, false);
    let native = Command::new("perf")
        .arg("--buildid-dir")
        .arg(root.path().join(".debug"))
        .args(["script", "--force", "-vvvv", "--kallsyms"])
        .arg(root.path().join("kallsyms"))
        .arg("-i")
        .arg(root.path().join("perf.data"))
        .output()
        .unwrap();
    assert!(native.status.success());
    assert!(!String::from_utf8_lossy(&native.stderr).contains("/kcore for kernel data"));
    let script = String::from_utf8(native.stdout).unwrap();
    assert_eq!(
        script.matches("cached_module_object+0x10 ([a])").count(),
        3,
        "{script}"
    );
    let mut expected = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(script.as_bytes(), &mut expected)
        .unwrap();
    for inline in [false, true] {
        let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            pyroclast::symbols::RustAddr2lineResolver::new(),
            &root.path().join("perf.data"),
            root.path(),
            [],
            &root.path().join("kallsyms"),
        );
        let actual = fold_perfdata_callchains_with_symbols(
            &bytes,
            FoldOptions {
                inline,
                count_periods: true,
            },
            &resolver,
        )
        .unwrap();
        assert_eq!(actual.as_bytes(), expected, "{script}");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kcore_accepts_shared_module_with_only_text_symbols() {
    use inferno::collapse::Collapse as _;
    use std::fmt::Write as _;

    let (root, bytes) = write_native_cached_module_fixture(true, false);
    let original = std::fs::read(root.path().join("module.elf")).unwrap();
    let elf = object::File::parse(original.as_slice()).unwrap();
    let id = elf.build_id().unwrap().unwrap();
    let hex = id.iter().fold(String::new(), |mut hex, byte| {
        write!(hex, "{byte:02x}").unwrap();
        hex
    });
    let mut builder = object::build::elf::Builder::read(original.as_slice()).unwrap();
    let text = builder
        .sections
        .iter()
        .find(|section| section.name.as_slice() == b".text")
        .unwrap()
        .id();
    // Keep the same ET_DYN and all section headers. Only remove symbol rows
    // which would make perf symbol-elf.c:dso__process_kernel_symbol create
    // additional module maps; .text only changes the original map's pgoff.
    for symbol in &mut builder.symbols {
        symbol.delete = symbol.section != Some(text);
    }
    let mut selected = Vec::new();
    builder.write(&mut selected).unwrap();
    assert_eq!(
        object::File::parse(selected.as_slice()).unwrap().kind(),
        object::ObjectKind::Dynamic
    );
    std::fs::write(
        pyroclast::symbols::perf_build_id_elf_path(&root.path().join(".debug"), &hex),
        selected,
    )
    .unwrap();

    let native = Command::new("perf")
        .arg("--buildid-dir")
        .arg(root.path().join(".debug"))
        .args(["script", "--force", "-vvvv", "--kallsyms"])
        .arg(root.path().join("kallsyms"))
        .arg("-i")
        .arg(root.path().join("perf.data"))
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let script = String::from_utf8(native.stdout).unwrap();
    assert!(
        String::from_utf8_lossy(&native.stderr).contains("/kcore for kernel data"),
        "script={script}\nstderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(script.matches("cached_module_object+0x10 ([a])").count(), 1);
    assert_eq!(script.matches("first+0x10 ([kernel.kallsyms])").count(), 2);
    let mut expected = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(script.as_bytes(), &mut expected)
        .unwrap();
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &expected);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kcore_rejects_executable_module_with_a_separate_data_map() {
    use inferno::collapse::Collapse as _;

    let (root, bytes) = write_native_cached_module_fixture_with_data(false, false, true);
    let native = Command::new("perf")
        .arg("--buildid-dir")
        .arg(root.path().join(".debug"))
        .args(["script", "--force", "-vvvv", "--kallsyms"])
        .arg(root.path().join("kallsyms"))
        .arg("-i")
        .arg(root.path().join("perf.data"))
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let script = String::from_utf8(native.stdout).unwrap();
    assert!(
        !String::from_utf8_lossy(&native.stderr).contains("/kcore for kernel data"),
        "script={script}\nstderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(script.matches("cached_module_object+0x10 ([a])").count(), 3);
    let mut expected = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(script.as_bytes(), &mut expected)
        .unwrap();
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &expected);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kcore_validates_module_maps_loaded_by_an_unrendered_event_ip() {
    use inferno::collapse::Collapse as _;
    const MODULE: u64 = 0xffff_ffff_c100_0010;
    const CORE: u64 = 0xffff_ffff_8100_0010;

    for data_symbol in [true, false] {
        let (root, bytes) = write_native_cached_module_queries(
            false,
            data_symbol,
            &[(MODULE, &[CORE]), (MODULE, &[MODULE])],
        );
        let native = Command::new("perf")
            .arg("--buildid-dir")
            .arg(root.path().join(".debug"))
            .args(["script", "--force", "-vvvv", "--kallsyms"])
            .arg(root.path().join("kallsyms"))
            .arg("-i")
            .arg(root.path().join("perf.data"))
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        let script = String::from_utf8(native.stdout).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&native.stderr).contains("/kcore for kernel data"),
            !data_symbol,
            "script={script}\nstderr={}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(
            script.matches("cached_module_object+0x10 ([a])").count(),
            usize::from(data_symbol),
            "{script}"
        );
        assert_eq!(
            script.matches("first+0x10 ([kernel.kallsyms])").count(),
            usize::from(!data_symbol),
            "{script}"
        );
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::default()
            .collapse(script.as_bytes(), &mut expected)
            .unwrap();
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &expected);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kcore_preserves_live_module_objects_until_core_replacement() {
    use inferno::collapse::Collapse as _;
    const MODULE: u64 = 0xffff_ffff_c100_0010;
    const CORE: u64 = 0xffff_ffff_8100_0010;

    for data_symbol in [false, true] {
        let (root, bytes) = write_native_module_object_queries(
            false,
            data_symbol,
            &[
                (MODULE, &[MODULE]),
                (MODULE, &[MODULE]),
                (CORE, &[CORE]),
                (MODULE, &[MODULE]),
            ],
            true,
        );
        let native = Command::new("perf")
            .arg("--buildid-dir")
            .arg(root.path().join(".debug"))
            .args(["script", "--force", "-vvvv", "--kallsyms"])
            .arg(root.path().join("kallsyms"))
            .arg("-i")
            .arg(root.path().join("perf.data"))
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        let script = String::from_utf8(native.stdout).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&native.stderr).contains("/kcore for kernel data"),
            !data_symbol,
            "script={script}\nstderr={}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(
            script.matches("cached_module_object+0x10 ([a])").count(),
            if data_symbol { 3 } else { 1 },
            "{script}"
        );
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::default()
            .collapse(script.as_bytes(), &mut expected)
            .unwrap();
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &expected);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_native_split_debug_module_fixture() -> (tempfile::TempDir, Vec<u8>, std::path::PathBuf) {
    use std::fmt::Write as _;

    const MODULE: u64 = 0xffff_ffff_c100_0010;
    const CORE: u64 = 0xffff_ffff_8100_0010;
    let (root, bytes) = write_native_module_object_queries(
        true,
        false,
        &[(MODULE, &[MODULE]), (CORE, &[CORE]), (MODULE, &[MODULE])],
        true,
    );
    let path = root.path().join("a.ko");
    let original = std::fs::read(&path).unwrap();
    let original_elf = object::File::parse(original.as_slice()).unwrap();
    let id = original_elf.build_id().unwrap().unwrap();
    let hex = id.iter().fold(String::new(), |mut hex, byte| {
        write!(hex, "{byte:02x}").unwrap();
        hex
    });
    let source = root.path().join("module.S");
    // Fill one page so objcopy's compact NOBITS layout is contiguous while
    // the runtime section remains separated by the explicit VMA gap.
    let mut assembly = std::fs::read_to_string(&source)
        .unwrap()
        .replace(".fill 512,1,0x90", ".fill 4096,1,0x90");
    assembly.push_str(".section .noinstr.text,\"ax\",@progbits\n.globl separate_module_text\n.type separate_module_text,@function\nseparate_module_text:\n.fill 512,1,0x90\n.size separate_module_text,.-separate_module_text\n");
    std::fs::write(&source, assembly).unwrap();
    let compiler = Command::new("cc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-e,cached_module_object",
            "-Wl,-Ttext=0xffffffffc1000000",
            "-Wl,--section-start=.noinstr.text=0xffffffffc1008000",
        ])
        .arg(format!("-Wl,--build-id=0x{hex}"))
        .arg("-o")
        .arg(&path)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        compiler.status.success(),
        "{}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    let runtime_image = std::fs::read(&path).unwrap();
    let mut builder = object::build::elf::Builder::read(runtime_image.as_slice()).unwrap();
    let text_sections = builder
        .sections
        .iter()
        .filter(|section| matches!(section.name.as_slice(), b".text" | b".noinstr.text"))
        .map(object::build::elf::Section::id)
        .collect::<Vec<_>>();
    // Linker-generated data symbols would independently reject kcore and
    // conceal the runtime-versus-debug executable-section difference.
    for symbol in &mut builder.symbols {
        symbol.delete = !symbol
            .section
            .is_some_and(|section| text_sections.contains(&section));
    }
    let mut selected = Vec::new();
    builder.write(&mut selected).unwrap();
    std::fs::write(&path, selected).unwrap();
    let cache = pyroclast::symbols::perf_build_id_elf_path(&root.path().join(".debug"), &hex);
    let copy = Command::new("objcopy")
        .arg("--only-keep-debug")
        .arg(&path)
        .arg(&cache)
        .output()
        .unwrap();
    assert!(
        copy.status.success(),
        "{}",
        String::from_utf8_lossy(&copy.stderr)
    );
    let runtime = std::fs::read(&path).unwrap();
    let debug = std::fs::read(&cache).unwrap();
    assert_split_debug_module_layout(&runtime, &debug, id);
    (root, bytes, cache)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn assert_split_debug_module_layout(runtime: &[u8], debug: &[u8], id: &[u8]) {
    use object::ObjectSection as _;
    use object::read::elf::SectionHeader as _;
    for file in [runtime, debug] {
        let elf = object::File::parse(file).unwrap();
        assert_eq!(elf.build_id().unwrap().unwrap(), id);
        assert!(
            elf.symbols()
                .any(|symbol| symbol.name() == Ok("separate_module_text"))
        );
    }
    let layout = |bytes: &[u8], name: &str| {
        let object::File::Elf64(elf) = object::File::parse(bytes).unwrap() else {
            panic!("fixture must be ELF64");
        };
        let section = elf.section_by_name(name).unwrap();
        let header = section.elf_section_header();
        (
            section.index(),
            header.sh_type(elf.endian()),
            header.sh_offset(elf.endian()),
            section.size(),
            section.address(),
            header.sh_flags(elf.endian()),
        )
    };
    assert_eq!(layout(runtime, ".dynsym").1, object::elf::SHT_DYNSYM);
    assert_eq!(layout(debug, ".dynsym").1, object::elf::SHT_NOBITS);
    let text = layout(runtime, ".text");
    let extra = layout(runtime, ".noinstr.text");
    let debug_text = layout(debug, ".text");
    let debug_extra = layout(debug, ".noinstr.text");
    assert!(extra.2 > text.2 + text.3);
    assert_ne!(extra.2, (text.2 + text.3).next_multiple_of(4096));
    assert!(
        debug_extra.2 <= debug_text.2 + debug_text.3,
        "debug text={debug_text:?}, extra={debug_extra:?}"
    );
    assert_eq!(
        (text.0, text.4, text.5),
        (debug_text.0, debug_text.4, debug_text.5)
    );
    assert_eq!(
        (extra.0, extra.4, extra.5),
        (debug_extra.0, debug_extra.4, debug_extra.5)
    );
    assert_eq!(debug_text.1, object::elf::SHT_NOBITS);
    assert_eq!(debug_extra.1, object::elf::SHT_NOBITS);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_split_debug_module_uses_runtime_section_layout_for_kcore_validation() {
    let (root, bytes, _) = write_native_split_debug_module_fixture();
    // symbol.c:1809 selects symbol and runtime ELFs independently. The
    // debug ELF's NOBITS sections use same-index runtime headers at
    // symbol-elf.c:1656, including the executable cutoff from line 1581.
    // The separated runtime section therefore prevents kcore replacement.
    let (script, stderr, native) = query_native_module_object(root.path());
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert_eq!(
        script.matches("cached_module_object+0x10 ([a])").count(),
        2,
        "{script}"
    );
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_split_debug_module_runtime_requires_matching_id_and_runtime_sections() {
    #[derive(Clone, Copy, Debug)]
    enum Runtime {
        Missing,
        WrongId,
        DebugOnly,
    }
    for control in [Runtime::Missing, Runtime::WrongId, Runtime::DebugOnly] {
        let (root, bytes, cache) = write_native_split_debug_module_fixture();
        let path = root.path().join("a.ko");
        match control {
            Runtime::Missing => std::fs::remove_file(&path).unwrap(),
            Runtime::DebugOnly => {
                std::fs::copy(&cache, &path).unwrap();
            }
            Runtime::WrongId => {
                let original = std::fs::read(&path).unwrap();
                let elf = object::File::parse(original.as_slice()).unwrap();
                let mut id = elf.build_id().unwrap().unwrap().to_vec();
                id[0] ^= 0xff;
                let mut builder = object::build::elf::Builder::read(original.as_slice()).unwrap();
                let note = builder
                    .sections
                    .iter_mut()
                    .find(|section| section.name.as_slice() == b".note.gnu.build-id")
                    .unwrap();
                let mut contents = Vec::new();
                contents.extend(4_u32.to_le_bytes());
                contents.extend(20_u32.to_le_bytes());
                contents.extend(object::elf::NT_GNU_BUILD_ID.to_le_bytes());
                contents.extend(b"GNU\0");
                contents.extend(&id);
                note.data = object::build::elf::SectionData::Data(contents.into());
                let mut rewritten = Vec::new();
                builder.write(&mut rewritten).unwrap();
                assert_eq!(
                    object::File::parse(rewritten.as_slice())
                        .unwrap()
                        .build_id()
                        .unwrap()
                        .unwrap(),
                    id
                );
                std::fs::write(&path, rewritten).unwrap();
            }
        }
        // symsrc__init (symbol-elf.c:1193) validates every source ID.
        // symsrc__possibly_runtime (1038) excludes debug-only NOBITS dynsym.
        // symbol.c:1846 falls back to the symbol source without a runtime ELF.
        let (script, stderr, native) = query_native_module_object(root.path());
        assert!(
            stderr.contains("/kcore for kernel data"),
            "{control:?}: {stderr}"
        );
        assert_eq!(
            script.matches("cached_module_object+0x10 ([a])").count(),
            1,
            "{control:?}: {script}"
        );
        assert!(
            script.contains("first+0x10 ([kernel.kallsyms])"),
            "{control:?}: {script}"
        );
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn split_debug_module_metadata_retains_each_runtime_source_pair() {
    use pyroclast::symbols::{KernelModuleSectionMap, SelectedObjectResolver, SymbolizerKind};
    let runner = pyroclast::process::RealCommandRunner::default();
    for kind in [SymbolizerKind::RustAddr2line, SymbolizerKind::Addr2line] {
        let (root, _, cache) = write_native_split_debug_module_fixture();
        let path = root.path().join("a.ko");
        let other_path = root.path().join("other.ko");
        std::fs::copy(&cache, &other_path).unwrap();
        let request = SymbolRequest {
            path: path.clone(),
            relative_address: 0,
            kernel_module_address: None,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        };
        let other_request = SymbolRequest {
            path: other_path.clone(),
            ..request.clone()
        };
        let resolver = SelectedObjectResolver::new(&runner, kind);
        let first = resolver
            .selected_object_module_metadata(&cache, &request)
            .unwrap();
        let second = resolver
            .selected_object_module_metadata(&cache, &other_request)
            .unwrap();
        assert_eq!(
            first.maps,
            [KernelModuleSectionMap {
                section: ".noinstr.text".into(),
                start: 0xffff_ffff_c100_8000,
            }]
        );
        assert!(second.maps.is_empty());
        // The native controls above establish opposite map effects for a
        // runtime ELF and a debug-only ELF. One shared symbol file must retain
        // both selections independently, including after removal or rewrite.
        std::fs::copy(&path, &other_path).unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(&cache).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &first,
            &resolver
                .selected_object_module_metadata(&cache, &request)
                .unwrap()
        ));
        assert!(std::sync::Arc::ptr_eq(
            &second,
            &resolver
                .selected_object_module_metadata(&cache, &other_request)
                .unwrap()
        ));
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn assert_native_split_debug_label_uses_runtime_name(runtime_text: bool) {
    use object::ObjectSection as _;
    let (root, bytes, cache) = write_native_split_debug_module_fixture();
    let path = root.path().join("a.ko");
    for (file, text_name) in [(&cache, !runtime_text), (&path, runtime_text)] {
        let original = std::fs::read(file).unwrap();
        let mut builder = object::build::elf::Builder::read(original.as_slice()).unwrap();
        let section = builder
            .sections
            .iter_mut()
            .find(|section| section.name.as_slice() == b".noinstr.text")
            .unwrap();
        if !text_name {
            section.name = b".cold".as_slice().into();
        }
        for symbol in &mut builder.symbols {
            if symbol.name.as_slice() == b"separate_module_text" {
                symbol.st_info = (symbol.st_info & !0xf) | object::elf::STT_NOTYPE;
            }
        }
        let mut rewritten = Vec::new();
        builder.write(&mut rewritten).unwrap();
        let elf = object::File::parse(rewritten.as_slice()).unwrap();
        let label = elf
            .symbols()
            .find(|symbol| symbol.name() == Ok("separate_module_text"))
            .unwrap();
        assert!(
            matches!(label.flags(), object::SymbolFlags::Elf { st_info, .. }
            if st_info & 0xf == object::elf::STT_NOTYPE)
        );
        let section = elf
            .section_by_index(label.section_index().unwrap())
            .unwrap();
        assert_eq!(
            section.name().unwrap(),
            if text_name { ".noinstr.text" } else { ".cold" }
        );
        std::fs::write(file, rewritten).unwrap();
    }
    let runtime = std::fs::read(&path).unwrap();
    let debug = std::fs::read(&cache).unwrap();
    let runtime_elf = object::File::parse(runtime.as_slice()).unwrap();
    let debug_elf = object::File::parse(debug.as_slice()).unwrap();
    assert_eq!(
        runtime_elf.build_id().unwrap(),
        debug_elf.build_id().unwrap()
    );
    let section_index = |elf: &object::File<'_>| {
        elf.symbols()
            .find(|symbol| symbol.name() == Ok("separate_module_text"))
            .unwrap()
            .section_index()
            .unwrap()
    };
    assert_eq!(section_index(&runtime_elf), section_index(&debug_elf));
    // symbol-elf.c:1665 checks a NOTYPE label's section name only after
    // substituting a NOBITS header from the same-index runtime section.
    let (script, stderr, native) = query_native_module_object(root.path());
    assert_eq!(
        stderr.contains("/kcore for kernel data"),
        !runtime_text,
        "{stderr}"
    );
    assert_eq!(
        script.matches("cached_module_object+0x10 ([a])").count(),
        if runtime_text { 2 } else { 1 },
        "{script}"
    );
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_split_debug_module_excludes_label_in_nontext_runtime_section() {
    assert_native_split_debug_label_uses_runtime_name(false);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_split_debug_module_keeps_label_in_text_runtime_section() {
    assert_native_split_debug_label_uses_runtime_name(true);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kcore_ignores_live_module_section_maps_when_build_id_is_wrong_or_missing() {
    use inferno::collapse::Collapse as _;
    const MODULE: u64 = 0xffff_ffff_c100_0010;
    const CORE: u64 = 0xffff_ffff_8100_0010;

    for missing in [false, true] {
        let (root, bytes) = write_native_module_object_queries(
            false,
            true,
            &[(MODULE, &[MODULE]), (CORE, &[CORE]), (MODULE, &[MODULE])],
            true,
        );
        let path = root.path().join("a.ko");
        let original = std::fs::read(&path).unwrap();
        let elf = object::File::parse(original.as_slice()).unwrap();
        let recorded_id = elf.build_id().unwrap().unwrap();
        let mut builder = object::build::elf::Builder::read(original.as_slice()).unwrap();
        let note = builder
            .sections
            .iter_mut()
            .find(|section| section.name.as_slice() == b".note.gnu.build-id")
            .unwrap();
        if missing {
            note.delete = true;
            builder.delete_orphan_segments();
        } else {
            let mut id = recorded_id.to_vec();
            id[0] ^= 0xff;
            let mut contents = Vec::new();
            contents.extend(4_u32.to_le_bytes());
            contents.extend(20_u32.to_le_bytes());
            contents.extend(3_u32.to_le_bytes());
            contents.extend(b"GNU\0");
            contents.extend(id);
            note.data = object::build::elf::SectionData::Data(contents.into());
        }
        let mut selected = Vec::new();
        builder.write(&mut selected).unwrap();
        let selected_id = object::File::parse(selected.as_slice())
            .unwrap()
            .build_id()
            .unwrap();
        assert_ne!(selected_id, Some(recorded_id));
        assert_eq!(selected_id.is_none(), missing);
        std::fs::write(path, selected).unwrap();

        let native = Command::new("perf")
            .arg("--buildid-dir")
            .arg(root.path().join(".debug"))
            .args(["script", "--force", "-vvvv", "--kallsyms"])
            .arg(root.path().join("kallsyms"))
            .arg("-i")
            .arg(root.path().join("perf.data"))
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        let script = String::from_utf8(native.stdout).unwrap();
        assert!(
            String::from_utf8_lossy(&native.stderr).contains("/kcore for kernel data"),
            "script={script}\nstderr={}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert!(!script.contains("cached_module_object"), "{script}");
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::default()
            .collapse(script.as_bytes(), &mut expected)
            .unwrap();
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &expected);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_native_module_path_replacement_fixture(
    same_short_name: bool,
) -> (tempfile::TempDir, Vec<u8>) {
    const MODULE: u64 = 0xffff_ffff_c100_0010;
    let (root, bytes) =
        write_native_module_object_queries(false, false, &[(MODULE, &[MODULE])], true);
    std::fs::remove_file(root.path().join("kcore")).unwrap();
    let original = std::fs::read(root.path().join("a.ko")).unwrap();
    let elf = object::File::parse(original.as_slice()).unwrap();
    let id = elf.build_id().unwrap().unwrap();
    let mut builder = object::build::elf::Builder::read(original.as_slice()).unwrap();
    for symbol in &mut builder.symbols {
        if symbol.name.as_slice() == b"cached_module_object" {
            symbol.name = b"replacement_module_object".as_slice().into();
        }
    }
    let mut replacement = Vec::new();
    builder.write(&mut replacement).unwrap();
    let directory = root.path().join("new");
    std::fs::create_dir(&directory).unwrap();
    // The fixture already contains [b]; use a genuinely new module for
    // the independent-name control.
    let path = directory.join(if same_short_name { "a.ko" } else { "c.ko" });
    std::fs::write(&path, replacement).unwrap();
    let header = pyroclast::perfdata::header::parse_header(&bytes).unwrap();
    let data_offset = usize::try_from(header.data_offset).unwrap();
    let mut replaced = bytes[..data_offset].to_vec();
    for record in pyroclast::perfdata::records::iter_records(&bytes, header).unwrap() {
        replaced.extend(record_bytes_with_misc(
            record.header.record_type,
            record.header.misc,
            record.payload,
        ));
        if record.header.record_type == 10 {
            let mut payload = mmap2_build_id_payload(
                u32::MAX,
                u32::MAX,
                0xffff_ffff_c100_0000,
                0x4000,
                0,
                path.to_str().unwrap(),
            );
            payload[32] = 20;
            payload[36..56].copy_from_slice(id);
            payload.resize(payload.len().next_multiple_of(8), 0);
            replaced.extend(record_bytes_with_misc(
                10,
                PERF_RECORD_MISC_CPUMODE_KERNEL | PERF_RECORD_MISC_MMAP_BUILD_ID,
                &payload,
            ));
        }
    }
    let size = u64::try_from(replaced.len() - data_offset).unwrap();
    put_u64(&mut replaced, 48, size);
    std::fs::write(root.path().join("perf.data"), &replaced).unwrap();
    (root, replaced)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_module_path_replacement_reuses_only_the_same_short_name_dso() {
    for same_short_name in [false, true] {
        let (root, bytes) = write_native_module_path_replacement_fixture(same_short_name);
        let (script, stderr, native) = query_native_module_object(root.path());
        // dsos.c:429 finds an existing module by short name and empty
        // identity. Its original long filename survives a later MMAP.
        assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
        assert_eq!(
            script.contains("cached_module_object+0x10 ([a])"),
            same_short_name,
            "{script}"
        );
        assert_eq!(
            script.contains("replacement_module_object+0x10 ([c])"),
            !same_short_name,
            "{script}"
        );
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_native_kernel_header_module_fixture(
    kernel: bool,
    relative: bool,
    name: &str,
    core_first: bool,
) -> (tempfile::TempDir, Vec<u8>) {
    let (root, bytes) = write_native_module_path_replacement_fixture(true);
    let old_path = root.path().join(format!("{name}.ko"));
    let new_path = root.path().join("new").join(format!("{name}.ko"));
    if name != "a" {
        std::fs::rename(root.path().join("a.ko"), &old_path).unwrap();
        std::fs::rename(root.path().join("new/a.ko"), &new_path).unwrap();
    }
    let old = std::fs::read(&old_path).unwrap();
    let elf = object::File::parse(old.as_slice()).unwrap();
    let id: &[u8; 20] = elf.build_id().unwrap().unwrap().try_into().unwrap();
    let header = pyroclast::perfdata::header::parse_header(&bytes).unwrap();
    let mut first_module = true;
    let mut records = pyroclast::perfdata::records::iter_records(&bytes, header)
        .unwrap()
        .into_iter()
        .filter_map(|record| {
            if record.header.record_type == 10 && first_module {
                first_module = false;
                None
            } else if record.header.record_type == 10 {
                let mut payload = mmap2_build_id_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_c100_0000,
                    0x4000,
                    0,
                    new_path.to_str().unwrap(),
                );
                payload[32] = 20;
                payload[36..56].copy_from_slice(id);
                payload.resize(payload.len().next_multiple_of(8), 0);
                Some(record_bytes_with_misc(10, record.header.misc, &payload))
            } else {
                Some(record_bytes_with_misc(
                    record.header.record_type,
                    record.header.misc,
                    record.payload,
                ))
            }
        })
        .collect::<Vec<_>>();
    if core_first {
        let path = root.path().join("kallsyms");
        let kallsyms = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, kallsyms.replace("[a]", &format!("[{name}]"))).unwrap();
        let core = 0xffff_ffff_8100_0010;
        records.insert(
            records.len() - 1,
            record_bytes_with_misc(
                PERF_RECORD_SAMPLE,
                PERF_RECORD_MISC_CPUMODE_KERNEL,
                &sample_payload_with_time(core, 11, 12, 999_999_999, [0xffff_ffff_ffff_ff80, core]),
            ),
        );
        std::fs::remove_file(&old_path).unwrap();
        std::fs::remove_file(&new_path).unwrap();
    }
    let cwd = std::env::current_dir().unwrap();
    let header_path = if relative {
        old_path.strip_prefix(&cwd).unwrap()
    } else {
        &old_path
    };
    let mut feature = build_id_event_payload(u32::MAX, id, header_path.to_str().unwrap());
    let misc = if kernel {
        PERF_RECORD_MISC_CPUMODE_KERNEL
    } else {
        PERF_RECORD_MISC_CPUMODE_USER
    };
    feature[4..6].copy_from_slice(&misc.to_le_bytes());
    let mut attr = file_attr_bytes(
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
        0,
        0,
    );
    put_u64(&mut attr, 16, 1);
    let mut bytes = perfdata_with_records_attrs_and_build_id_feature([attr], records, &feature);
    put_u64(&mut bytes, 16, 144);
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    (root, bytes)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kernel_build_id_header_binds_module_by_short_name_but_user_header_does_not() {
    for (kernel, relative) in [(true, false), (false, false), (true, true), (false, true)] {
        let (root, bytes) = write_native_kernel_header_module_fixture(kernel, relative, "a", false);
        let (script, _, native) = query_native_module_object(root.path());
        // header.c:2550 canonicalizes kernel module headers with
        // dso__set_module_info. USER headers retain their ordinary basename.
        assert_eq!(
            script.contains("cached_module_object+0x10 ("),
            kernel,
            "{script}"
        );
        assert_eq!(
            script.contains("replacement_module_object+0x10 ("),
            !kernel,
            "{script}"
        );
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_kernel_header_ordinary_vsyscall_module_name_keeps_original_path() {
    let (root, bytes) = write_native_kernel_header_module_fixture(true, true, "vsyscall", false);
    let (script, _, native) = query_native_module_object(root.path());
    // dso.c:436 excludes reserved prefixes only in an originally bracketed
    // basename. An ordinary vsyscall.ko is a real [vsyscall] module DSO.
    assert!(script.contains("cached_module_object+0x10 ("), "{script}");
    assert!(!script.contains("replacement_module_object"), "{script}");
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_relative_header_module_falls_back_to_file_kallsyms_after_core_load() {
    let (root, bytes) = write_native_kernel_header_module_fixture(true, true, "a", true);
    let (script, stderr, native) = query_native_module_object(root.path());
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert!(script.contains("first+0x10 ("), "{script}");
    assert!(!script.contains("cached_module_object"), "{script}");
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_bound_module_kallsyms_names_are_not_reclassified_as_core_or_vdso() {
    // symbol.c:maps__split_kallsyms (914) finds the already-bound module by
    // short name. dso.c:436 exclusions apply to original bracketed basenames,
    // not to canonical names produced from ordinary .ko filenames.
    for name in ["vdso", "vdso32", "vdsox32", "kernel_test"] {
        let (root, bytes) = write_native_kernel_header_module_fixture(true, true, name, true);
        let (script, stderr, native) = query_native_module_object(root.path());
        assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
        assert!(script.contains("first+0x10 ("), "{name}: {script}");
        assert!(!script.contains("cached_module_object"), "{name}: {script}");
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_module_event_ip_discovers_live_build_id_before_cache_selection() {
    use std::fmt::Write as _;
    const MODULE: u64 = 0xffff_ffff_c100_0010;
    const CORE: u64 = 0xffff_ffff_8100_0010;

    for cache_data_symbol in [true, false] {
        let (root, bytes) = write_native_module_object_queries(
            false,
            true,
            &[(MODULE, &[CORE]), (MODULE, &[MODULE])],
            true,
        );
        let original = std::fs::read(root.path().join("module.elf")).unwrap();
        let elf = object::File::parse(original.as_slice()).unwrap();
        let id = elf.build_id().unwrap().unwrap();
        let hex = id.iter().fold(String::new(), |mut hex, byte| {
            write!(hex, "{byte:02x}").unwrap();
            hex
        });
        let mut builder = object::build::elf::Builder::read(original.as_slice()).unwrap();
        let text = builder
            .sections
            .iter()
            .find(|section| section.name.as_slice() == b".text")
            .unwrap()
            .id();
        for symbol in &mut builder.symbols {
            symbol.delete = symbol.section != Some(text);
        }
        let mut text_only = Vec::new();
        builder.write(&mut text_only).unwrap();
        assert_eq!(
            object::File::parse(text_only.as_slice())
                .unwrap()
                .build_id()
                .unwrap(),
            Some(id)
        );
        let cache = pyroclast::symbols::perf_build_id_elf_path(&root.path().join(".debug"), &hex);
        let (cached, live) = if cache_data_symbol {
            (&original, &text_only)
        } else {
            (&text_only, &original)
        };
        std::fs::write(cache, cached).unwrap();
        std::fs::write(root.path().join("a.ko"), live).unwrap();

        // symbol.c:dso__load discovers an undefined ID from the live ELF
        // before selecting the cache. Use an ordinary MMAP with no ID.
        let header = pyroclast::perfdata::header::parse_header(&bytes).unwrap();
        let data_offset = usize::try_from(header.data_offset).unwrap();
        let mut no_id = bytes[..data_offset].to_vec();
        for record in pyroclast::perfdata::records::iter_records(&bytes, header).unwrap() {
            if record.header.record_type == 10 {
                let mut payload = mmap_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_c100_0000,
                    0x4000,
                    0,
                    root.path().join("a.ko").to_str().unwrap(),
                );
                payload.resize(payload.len().next_multiple_of(8), 0);
                no_id.extend(record_bytes_with_misc(
                    1,
                    PERF_RECORD_MISC_CPUMODE_KERNEL,
                    &payload,
                ));
            } else {
                no_id.extend(record_bytes_with_misc(
                    record.header.record_type,
                    record.header.misc,
                    record.payload,
                ));
            }
        }
        let data_size = u64::try_from(no_id.len() - data_offset).unwrap();
        put_u64(&mut no_id, 48, data_size);
        std::fs::write(root.path().join("perf.data"), &no_id).unwrap();
        let summary = summarize_perfdata(&no_id).unwrap();
        assert!(
            summary
                .mmap_table
                .resolve_ref(11, MODULE)
                .unwrap()
                .build_id
                .is_none()
        );

        let (script, stderr, native) = query_native_module_object(root.path());
        assert_eq!(
            stderr.contains("/kcore for kernel data"),
            !cache_data_symbol,
            "native must use cache maps rather than live maps\nscript={script}\nstderr={stderr}"
        );
        assert_module_symbol_routes_match_native(root.path(), &no_id, &script, &native);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn query_native_module_object(root: &std::path::Path) -> (String, String, Vec<u8>) {
    use inferno::collapse::Collapse as _;
    let native = Command::new("perf")
        .arg("--buildid-dir")
        .arg(root.join(".debug"))
        .args(["script", "--force", "-vvvv", "--kallsyms"])
        .arg(root.join("kallsyms"))
        .arg("-i")
        .arg(root.join("perf.data"))
        .env("DEBUGINFOD_URLS", "")
        .output()
        .unwrap();
    let stderr = String::from_utf8(native.stderr).unwrap();
    assert!(native.status.success(), "{stderr}");
    let script = String::from_utf8(native.stdout).unwrap();
    let mut folded = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(script.as_bytes(), &mut folded)
        .unwrap();
    (script, stderr, folded)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn kernel_symbol_batches_preserve_native_module_core_cursor_order() {
    use pyroclast::symbols::{SelectedObjectResolver, SymbolizerKind};
    use std::fmt::Write as _;
    const MODULE: u64 = 0xffff_ffff_c100_0010;
    const CORE: u64 = 0xffff_ffff_8100_0010;

    for data_symbol in [true, false] {
        let (root, bytes) = write_native_cached_module_queries(
            false,
            data_symbol,
            &[
                (MODULE, &[MODULE]),
                (MODULE + 0x10, &[MODULE + 0x10]),
                (CORE, &[CORE]),
                (MODULE, &[MODULE]),
            ],
        );
        let (script, _, folded) = query_native_module_object(root.path());
        assert_eq!(
            script.matches("cached_module_object+0x").count(),
            if data_symbol { 3 } else { 1 },
            "{script}"
        );
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &folded);
        let summary = summarize_perfdata(&bytes).unwrap();
        let requests = [MODULE, MODULE + 0x10, CORE, MODULE].map(|ip| {
            let mapping = summary.mmap_table.resolve_ref(11, ip).unwrap();
            SymbolRequest {
                path: mapping.path.into(),
                relative_address: mapping.relative_address,
                kernel_module_address: mapping.kernel_module_address,
                kernel_mapping_range: Some((mapping.start, mapping.end)),
                build_id: mapping.build_id.map(|id| {
                    id.iter().fold(String::new(), |mut hex, byte| {
                        write!(hex, "{byte:02x}").unwrap();
                        hex
                    })
                }),
                file_identity: mapping.file_identity,
                kernel_relocation: mapping.kernel_relocation,
            }
        });
        let runner = pyroclast::process::RealCommandRunner::default();
        for symbolizer in [SymbolizerKind::RustAddr2line, SymbolizerKind::Addr2line] {
            let make_resolver = || {
                perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                    SelectedObjectResolver::new(&runner, symbolizer),
                    &root.path().join("perf.data"),
                    root.path(),
                    [],
                    &root.path().join("kallsyms"),
                )
            };
            let sequential = make_resolver();
            let expected = requests
                .iter()
                .flat_map(|request| {
                    sequential
                        .resolve_batch(std::slice::from_ref(request))
                        .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(expected[0].as_deref(), Some("cached_module_object"));
            assert_eq!(
                expected[3].as_deref(),
                Some(if data_symbol {
                    "cached_module_object"
                } else {
                    "first+0x10"
                })
            );
            assert_eq!(
                make_resolver().resolve_batch(&requests).unwrap(),
                expected,
                "{symbolizer:?} data={data_symbol}: {script}"
            );
            for inline in [false, true] {
                let resolve = |resolver: &pyroclast::symbols::PerfSymbolResolver<
                    SelectedObjectResolver<'_, pyroclast::process::RealCommandRunner>,
                >,
                               batch: &[SymbolRequest]| {
                    if inline {
                        resolver.resolve_frame_batch_with_metadata(batch)
                    } else {
                        resolver.resolve_base_frame_batch_with_metadata(batch)
                    }
                    .unwrap()
                };
                let sequential = make_resolver();
                let expected = requests
                    .iter()
                    .flat_map(|request| resolve(&sequential, std::slice::from_ref(request)))
                    .collect::<Vec<_>>();
                assert_eq!(
                    resolve(&make_resolver(), &requests),
                    expected,
                    "{symbolizer:?} inline={inline} data={data_symbol}"
                );
            }
        }
    }
}
