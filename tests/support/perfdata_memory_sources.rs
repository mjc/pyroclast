use super::*;
use object::ObjectSection as _;

const DATA: &str = "PYROCLAST_MEMORY_SOURCE_DATA";
const EXPECTED: &str = "PYROCLAST_MEMORY_SOURCE_FOLDED";

fn memory_fixture(form: UnwindReplacementMmap, changed: bool) -> UnwindReplacementFixture {
    let mut fixture = unwind_replacement_fixture(false, false, true, form);
    let root = fixture.root.path();
    let source = root.join("memory.S");
    // perf unwind-libdw.c:185-245 selects memory from the current map, while
    // its __report_module retains old CFI for a same-base replacement.
    // A location expression reads .data outside the captured user stack.
    std::fs::write(
        &source,
        r#".text
.globl identity_leaf
.type identity_leaf,@function
identity_leaf:
.cfi_startproc
.cfi_def_cfa %rsp,8
#ifdef CACHE_CFI
.cfi_escape 0x10,0x10,0x09,0x0e,0x00,0x30,0x40,0,0,0,0,0
#else
.cfi_undefined %rip
#endif
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
.data
.globl return_word
return_word:
#ifdef LIVE_WORD
.quad caller_live+1
#else
.quad caller_cache+1
#endif
.section .note.GNU-stack,"",@progbits
"#,
    )
    .unwrap();
    let cached = pyroclast::symbols::perf_build_id_elf_path_for_dso(
        &fixture.home.join(".debug"),
        &root.join("old-missing.elf"),
        "2222222222222222222222222222222222222222",
    );
    compile_memory_object(&source, &cached, true, false);
    compile_memory_object(&source, &root.join("replacement.elf"), false, changed);
    fixture.expected_ips[1][2] = if changed { 0x0040_1020 } else { 0x0040_1040 };
    fixture
}

fn compile_memory_object(
    source: &std::path::Path,
    binary: &std::path::Path,
    cached: bool,
    changed: bool,
) {
    let output = Command::new("cc")
        .args([
            "-nostdlib",
            "-no-pie",
            "-Wl,-e,identity_leaf,-Ttext=0x401000,-Tdata=0x403000,--eh-frame-hdr",
        ])
        .arg(if cached { "-DCACHE_CFI" } else { "-DLIVE_CFI" })
        .arg(if changed {
            "-DLIVE_WORD"
        } else {
            "-DCACHE_WORD"
        })
        .arg(if cached {
            "-Wl,--build-id=0x2222222222222222222222222222222222222222"
        } else {
            "-Wl,--build-id=0x1111111111111111111111111111111111111111"
        })
        .arg(source)
        .arg("-o")
        .arg(binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let bytes = std::fs::read(binary).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    assert_eq!(
        object.section_by_name(".data").unwrap().address(),
        0x0040_3000
    );
}

fn check_fold_route(name: &str, file_route: bool) {
    if let Some(data) = std::env::var_os(DATA) {
        let data = std::path::PathBuf::from(data);
        let folded = if file_route {
            pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                &data,
                FoldOptions::default(),
                &CfiAddressResolver,
            )
        } else {
            fold_perfdata_callchains_with_symbols(
                &std::fs::read(data).unwrap(),
                FoldOptions::default(),
                &CfiAddressResolver,
            )
        }
        .unwrap();
        assert_eq!(folded, std::env::var(EXPECTED).unwrap());
        return;
    }
    let mut failures = Vec::new();
    for form in [
        UnwindReplacementMmap::Mmap,
        UnwindReplacementMmap::Mmap2,
        UnwindReplacementMmap::BuildId,
    ] {
        for changed in [false, true] {
            let fixture = memory_fixture(form, changed);
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("HOME", &fixture.home)
                .env(DATA, &fixture.data)
                .env(EXPECTED, unwind_replacement_expected_fold(&fixture))
                .output()
                .unwrap();
            if !output.status.success() {
                failures.push(format!(
                    "{form:?} changed={changed}: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn byte_folding_reads_current_mapping_words_with_retained_old_cfi() {
    check_fold_route(
        "memory_sources::byte_folding_reads_current_mapping_words_with_retained_old_cfi",
        false,
    );
}

#[test]
fn file_folding_reads_current_mapping_words_with_retained_old_cfi() {
    check_fold_route(
        "memory_sources::file_folding_reads_current_mapping_words_with_retained_old_cfi",
        true,
    );
}

#[test]
fn perf_script_reads_current_mapping_words_with_retained_old_cfi() {
    let mut failures = Vec::new();
    for form in [
        UnwindReplacementMmap::Mmap,
        UnwindReplacementMmap::Mmap2,
        UnwindReplacementMmap::BuildId,
    ] {
        for changed in [false, true] {
            let fixture = memory_fixture(form, changed);
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
                assert!(output.status.success(), "{output:?}");
                let script = String::from_utf8(output.stdout).unwrap();
                let ips = script
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
                if ips != fixture.expected_ips {
                    failures.push(format!(
                        "{form:?} changed={changed} {symbolizer}: expected {:?}, got {ips:?}",
                        fixture.expected_ips
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
