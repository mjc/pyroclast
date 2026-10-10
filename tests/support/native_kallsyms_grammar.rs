use super::{
    assert_module_symbol_routes_match_native,
    perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources,
    query_native_module_kallsyms, summarize_perfdata, write_native_ordered_module_kallsyms_fixture,
};
use pyroclast::symbols::{
    SelectedObjectResolver, SymbolDsoName, SymbolLookup, SymbolRequest, SymbolResolver as _,
    SymbolizerKind,
};

fn assert_native_live_type_row(
    symbol_type: &str,
    expected_middle_name: &str,
    expected_middle_offset: u64,
    expected_first_end: u64,
) {
    const BASE: u64 = 0xffff_ffff_8100_0000;
    let rows = format!(
        "ffffffff81000000 T _stext\nffffffff81000100 {symbol_type} poison\nffffffff81001000 T guard\n"
    );
    let queries = [BASE + 0x10, BASE + 0x110, BASE + 0x1010];
    let (root, bytes) =
        write_native_ordered_module_kallsyms_fixture(&rows, &queries, true, ["[a]", "[b]"]);
    let kallsyms = root.path().join("kallsyms");
    assert!(!root.path().join("kcore").exists());
    assert!(!root.path().join(".debug").exists());
    assert!(!root.path().join("System.map").exists());
    assert!(
        std::fs::read_dir(root.path().join("symfs"))
            .expect("isolated symfs")
            .next()
            .is_none()
    );

    // Establish the installed native parser's result before querying Pyroclast.
    let (script, stderr, native) =
        query_native_module_kallsyms(root.path(), &[("_stext", expected_first_end)]);
    let selected_source = format!("Using {} for symbols", kallsyms.display());
    assert!(stderr.contains(&selected_source), "{script}\n{stderr}");
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    let expected_frames = [
        "_stext+0x10".to_owned(),
        format!("{expected_middle_name}+0x{expected_middle_offset:x}"),
        "guard+0x10".to_owned(),
    ];
    for (ip, expected_frame) in queries.into_iter().zip(&expected_frames) {
        let address = format!("{ip:x}");
        assert!(
            script.lines().any(|line| {
                let mut fields = line.split_whitespace();
                fields.next() == Some(address.as_str())
                    && fields.next() == Some(expected_frame.as_str())
                    && fields.next() == Some("([kernel.kallsyms])")
            }),
            "native frame at {address}: {expected_frame}\n{script}\n{stderr}"
        );
    }
    let expected_folded =
        format!("query_00;_stext 1\nquery_01;{expected_middle_name} 1\nquery_02;guard 1\n");
    assert_eq!(native, expected_folded.as_bytes(), "{script}\n{stderr}");

    let summary = summarize_perfdata(&bytes).expect("fixture summary");
    let runner = pyroclast::process::RealCommandRunner::default();
    for metadata in [false, true] {
        let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            SelectedObjectResolver::new(&runner, SymbolizerKind::RustAddr2line),
            &root.path().join("perf.data"),
            root.path(),
            [],
            &kallsyms,
        );
        for (ip, expected_frame) in queries.into_iter().zip(&expected_frames) {
            let mapping = summary
                .mmap_table
                .resolve_ref(11, ip)
                .expect("recorded core mapping");
            assert!(mapping.path.starts_with("[kernel.kallsyms]"));
            assert!(mapping.build_id.is_none());
            let request = SymbolRequest {
                addr2line_address: None,
                symbol_lookup: SymbolLookup::VirtualAddress,
                path: mapping.path.into(),
                relative_address: mapping.relative_address,
                kernel_module_address: None,
                kernel_mapping_range: Some((mapping.start, mapping.end)),
                build_id: None,
                file_identity: mapping.file_identity,
                kernel_relocation: mapping.kernel_relocation,
            };
            if metadata {
                let actual = resolver
                    .resolve_frame_batch_with_metadata(&[request])
                    .expect("live core frames");
                assert_eq!(actual.len(), 1);
                assert_eq!(
                    actual[0].kernel_dso,
                    SymbolDsoName::Mapping,
                    "native-first oracle\n{script}\n{stderr}"
                );
                assert_eq!(
                    actual[0].frames,
                    std::slice::from_ref(expected_frame),
                    "native-first oracle\n{script}\n{stderr}"
                );
            } else {
                let actual = resolver
                    .resolve_batch(&[request])
                    .expect("live core symbol");
                assert_eq!(actual.len(), 1);
                assert_eq!(
                    actual[0].as_deref(),
                    Some(expected_frame.as_str()),
                    "native-first oracle\n{script}\n{stderr}"
                );
            }
        }
    }
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[test]
fn native_live_kallsyms_accepts_single_byte_type() {
    assert_native_live_type_row("T", "poison", 0x10, 0xffff_ffff_8100_0100);
}

#[test]
fn native_live_kallsyms_rejects_multi_byte_type() {
    assert_native_live_type_row("Textual", "_stext", 0x110, 0xffff_ffff_8100_1000);
}

struct GrammarCase {
    label: &'static str,
    middle: &'static str,
    frame: &'static str,
    guard: &'static str,
}

const GRAMMAR_CASES: &[GrammarCase] = &[
    GrammarCase {
        label: "space",
        middle: "ffffffff81000100 T poison\n",
        frame: "poison+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "address tab",
        middle: "ffffffff81000100\tT poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "type tab",
        middle: "ffffffff81000100 T\tpoison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "leading space",
        middle: " ffffffff81000100 T poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "leading tab",
        middle: "\tffffffff81000100 T poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "Textual",
        middle: "ffffffff81000100 Textual poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "plus",
        middle: "+ffffffff81000100 T poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "minus",
        middle: "-ffffffff81000100 T poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "prefix",
        middle: "0xffffffff81000100 T poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "wrapping hex",
        middle: "1ffffffff81000100 T poison\n",
        frame: "poison+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "spaces in name",
        middle: "ffffffff81000100 T poison with spaces\n",
        frame: "poison with spaces+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "leading name space",
        middle: "ffffffff81000100 T  poison\n",
        frame: " poison+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "trailing CR",
        middle: "ffffffff81000100 T poison\r\n",
        frame: "poison\r+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "C visible NUL",
        middle: "ffffffff81000100 T poison\0ignored\n",
        frame: "poison+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "space suffix",
        middle: "ffffffff81000100 T poison [a]\n",
        frame: "poison [a]+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "adjacent malformed",
        middle: "bad row\nffffffff81000100 T poison\n",
        frame: "poison+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "blank consumes next",
        middle: "\nffffffff81000100 T poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "hex LF consumes next",
        middle: "ffffffff81000080\nffffffff81000100 T poison\n",
        frame: "_stext+0x110",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "separator LF consumes guard",
        middle: "ffffffff81000100 T\n",
        frame: "_stext+0x110",
        guard: "_stext+0x3010",
    },
    GrammarCase {
        label: "empty visible name",
        middle: "ffffffff81000100 T \n",
        frame: "+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "NUL first",
        middle: "ffffffff81000100 T \0ignored\n",
        frame: "+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "NUL before suffix",
        middle: "ffffffff81000100 T poison\0\t[a]\n",
        frame: "poison+0x10",
        guard: "guard+0x10",
    },
    GrammarCase {
        label: "type LF consumes guard",
        middle: "ffffffff81000100 \n",
        frame: "_stext+0x110",
        guard: "_stext+0x3010",
    },
];

fn live_case(case: &GrammarCase, check_public: bool) {
    const BASE: u64 = 0xffff_ffff_8100_0000;
    let rows = format!(
        "ffffffff81000000 T _stext\n{}ffffffff81003000 T guard\nffffffff81004000 T tail",
        case.middle
    );
    let queries = [BASE + 0x10, BASE + 0x110, BASE + 0x3010, BASE + 0x4010];
    let (root, bytes) =
        write_native_ordered_module_kallsyms_fixture(&rows, &queries, true, ["[a]", "[b]"]);
    assert!(!root.path().join("kcore").exists());
    assert!(!root.path().join(".debug").exists());
    assert!(!root.path().join("System.map").exists());
    assert!(
        std::fs::read_dir(root.path().join("symfs"))
            .unwrap()
            .next()
            .is_none()
    );
    let (script, stderr, native) = query_native_module_kallsyms(root.path(), &[]);
    assert!(
        stderr.contains(&format!(
            "Using {} for symbols",
            root.path().join("kallsyms").display()
        )),
        "{}: {script}\n{stderr}",
        case.label
    );
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    for (ip, frame) in queries
        .into_iter()
        .zip(["_stext+0x10", case.frame, case.guard, "tail+0x10"])
    {
        let expected = format!("{ip:x} {frame} ([kernel.kallsyms])");
        assert!(
            script
                .split('\n')
                .any(|line| line.trim_start_matches([' ', '\t']) == expected),
            "{}: native complete frame {expected:?}\n{script}\n{stderr}",
            case.label
        );
    }
    if check_public {
        assert_public_core_frames(
            root.path(),
            &bytes,
            &queries,
            &["_stext+0x10", case.frame, case.guard, "tail+0x10"],
            &script,
            &stderr,
        );
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
    }
}

#[test]
fn native_live_kallsyms_corpus_guards() {
    for case in GRAMMAR_CASES {
        live_case(case, false);
    }
}

macro_rules! live_grammar_tests {
    ($($name:ident: $index:literal),* $(,)?) => {
        $(#[test]
        fn $name() {
            live_case(&GRAMMAR_CASES[$index], true);
        })*
    };
}

live_grammar_tests! {
    native_row_literal_space: 0,
    native_row_address_tab: 1,
    native_row_type_tab: 2,
    native_row_leading_space: 3,
    native_row_leading_tab: 4,
    native_row_textual: 5,
    native_row_unsigned_plus: 6,
    native_row_unsigned_minus: 7,
    native_row_hex_prefix: 8,
    native_row_wrapping_hex: 9,
    native_row_name_spaces: 10,
    native_row_name_leading_space: 11,
    native_row_name_cr: 12,
    native_row_name_nul_suffix: 13,
    native_row_space_module_suffix: 14,
    native_row_adjacent_malformed: 15,
    native_row_blank_consumes_next: 16,
    native_row_hex_lf_consumes_next: 17,
    native_row_separator_lf_consumes_guard: 18,
    native_row_empty_name: 19,
    native_row_nul_first: 20,
    native_row_nul_before_module_suffix: 21,
    native_row_type_lf_consumes_guard: 22,
}

fn assert_public_core_frames(
    root: &std::path::Path,
    bytes: &[u8],
    queries: &[u64],
    frames: &[&str],
    script: &str,
    stderr: &str,
) {
    let summary = summarize_perfdata(bytes).unwrap();
    let runner = pyroclast::process::RealCommandRunner::default();
    for metadata in [false, true] {
        let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            SelectedObjectResolver::new(&runner, SymbolizerKind::RustAddr2line),
            &root.join("perf.data"),
            root,
            [],
            &root.join("kallsyms"),
        );
        for (&ip, &frame) in queries.iter().zip(frames) {
            let mapping = summary.mmap_table.resolve_ref(11, ip).unwrap();
            assert!(mapping.build_id.is_none());
            let request = SymbolRequest {
                addr2line_address: None,
                symbol_lookup: SymbolLookup::VirtualAddress,
                path: mapping.path.into(),
                relative_address: mapping.relative_address,
                kernel_module_address: None,
                kernel_mapping_range: Some((mapping.start, mapping.end)),
                build_id: None,
                file_identity: mapping.file_identity,
                kernel_relocation: mapping.kernel_relocation,
            };
            if metadata {
                let actual = resolver
                    .resolve_frame_batch_with_metadata(&[request])
                    .unwrap();
                assert_eq!(actual[0].frames, [frame], "{script}\n{stderr}");
                assert_eq!(actual[0].kernel_dso, SymbolDsoName::Mapping);
            } else {
                let actual = resolver.resolve_batch(&[request]).unwrap();
                assert_eq!(actual[0].as_deref(), Some(frame), "{script}\n{stderr}");
            }
        }
    }
}

fn module_suffix_case(index: usize, check_public: bool) {
    let (suffix, expected, module) = [
        (" [a]", "[unknown]", false),
        ("\t[a]", "poison+0x10", true),
        ("\t[a] ", "[unknown]", false),
        ("\t[a]\tignored", "[unknown]", false),
    ][index];
    let rows = format!(
        "ffffffff81000000 T _stext\nffffffff81001000 T core_tail\nffffffffc1000000 T poison{suffix}\nffffffffc1001000 T guard\t[a]\n"
    );
    let (root, bytes) = write_native_ordered_module_kallsyms_fixture(
        &rows,
        &[
            0xffff_ffff_8100_0010,
            0xffff_ffff_c100_0010,
            0xffff_ffff_c100_1010,
        ],
        true,
        ["[a]", "[b]"],
    );
    let (script, stderr, native) = query_native_module_kallsyms(root.path(), &[]);
    assert!(
        stderr.contains(&format!(
            "Using {} for symbols",
            root.path().join("kallsyms").display()
        )),
        "{stderr}"
    );
    assert!(!root.path().join("kcore").exists());
    assert!(!root.path().join(".debug").exists());
    assert!(
        script.contains(&format!("c1000010 {expected} (")),
        "suffix={suffix:?}\n{script}\n{stderr}"
    );
    if module {
        assert!(script.contains("poison+0x10 ([a])"), "{script}");
    } else if let Some(module_suffix) = suffix.strip_prefix('\t') {
        assert!(
            stderr.contains(&format!("for \"{module_suffix}\" module")),
            "{stderr}"
        );
    }
    assert!(script.contains("guard+0x10 ([a])"), "{script}\n{stderr}");
    if check_public {
        assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
    }
}

#[test]
fn native_live_kallsyms_suffix_guards() {
    for index in 0..4 {
        module_suffix_case(index, false);
    }
}

#[test]
fn native_suffix_space_is_not_module() {
    module_suffix_case(0, true);
}

#[test]
fn native_suffix_canonical_tab() {
    module_suffix_case(1, true);
}

#[test]
fn native_suffix_trailing_space_is_exact() {
    module_suffix_case(2, true);
}

#[test]
fn native_suffix_second_tab_is_exact() {
    module_suffix_case(3, true);
}

fn selected_cache_case(full_name: bool, check_public: bool) {
    let (rows, expected) = if full_name {
        (
            "ffffffff81000000 T _stext\nffffffff81000008 Textual poison\nffffffff81000010 T cached full name\nffffffff81001000 T tail\n",
            "cached full name+0x0",
        )
    } else {
        (
            "ffffffff81000000 T _stext\nffffffff81000008 Textual poison\nffffffff81001000 T tail\n",
            "_stext+0x10",
        )
    };
    selected_cache_rows(rows, expected, check_public);
}

fn selected_cache_rows(rows: &str, expected: &str, check_public: bool) {
    use inferno::collapse::Collapse as _;
    let (root, bytes) = super::write_native_cached_kallsyms_reference_fixture(rows, false);
    let cache = root
        .path()
        .join(".debug/[kernel.kallsyms]")
        .join("a5".repeat(20))
        .join("kallsyms");
    std::fs::remove_file(root.path().join("kallsyms")).unwrap();
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), rows);
    assert!(!root.path().join("kcore").exists());
    assert!(!root.path().join("System.map").exists());
    assert!(
        !pyroclast::symbols::perf_build_id_elf_path(&root.path().join(".debug"), &"a5".repeat(20))
            .exists()
    );
    let perf = std::process::Command::new("perf")
        .args(["script", "--force", "-vvvv", "--kallsyms"])
        .arg(&cache)
        .arg("--symfs")
        .arg(root.path().join("symfs"))
        .arg("-i")
        .arg(root.path().join("perf.data"))
        .env("DEBUGINFOD_URLS", "")
        .output()
        .unwrap();
    let script = String::from_utf8(perf.stdout).unwrap();
    let stderr = String::from_utf8(perf.stderr).unwrap();
    assert!(perf.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("Using {} for symbols", cache.display())),
        "{script}\n{stderr}"
    );
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert!(
        script.contains(&format!("{expected} ([kernel.kallsyms])")),
        "{script}\n{stderr}"
    );
    assert!(!stderr.contains("symbol__new: poison "), "{stderr}");
    assert!(!stderr.contains("symbol__new: $poison "), "{stderr}");
    let mut native = Vec::new();
    inferno::collapse::perf::Folder::default()
        .collapse(std::io::Cursor::new(script.as_bytes()), &mut native)
        .unwrap();
    if check_public {
        let runner = pyroclast::process::RealCommandRunner::default();
        let missing = root.path().join("missing-system-source");
        for symbolizer in [SymbolizerKind::RustAddr2line, SymbolizerKind::Addr2line] {
            for inline in [false, true] {
                for file in [false, true] {
                    let resolver =
                        perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                            SelectedObjectResolver::new(&runner, symbolizer),
                            &root.path().join("perf.data"),
                            root.path(),
                            [],
                            &missing,
                        )
                        .with_live_kernel_notes_path(missing.clone());
                    let options = super::FoldOptions {
                        inline,
                        count_periods: true,
                    };
                    let actual = if file {
                        pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                            &root.path().join("perf.data"),
                            options,
                            &resolver,
                        )
                    } else {
                        super::fold_perfdata_callchains_with_symbols(&bytes, options, &resolver)
                    }
                    .unwrap();
                    assert_eq!(
                        actual.as_bytes(),
                        native,
                        "{symbolizer:?}, inline={inline}, file={file}\n{script}\n{stderr}"
                    );
                }
            }
        }
    }
}

#[test]
fn native_selected_cached_kallsyms_grammar_guards() {
    selected_cache_case(false, false);
    selected_cache_case(true, false);
}

#[test]
fn native_selected_cached_kallsyms_grammar_public_routes() {
    selected_cache_case(true, true);
}

#[test]
fn native_selected_cached_kallsyms_rejects_textual() {
    selected_cache_case(false, true);
}

fn selected_cache_policy(symbol_type: &str, name: &str, expected: &str) {
    let rows = format!(
        "ffffffff81000000 T _stext\nffffffff81000008 {symbol_type} {name}\nffffffff81001000 T tail\n"
    );
    selected_cache_rows(&rows, expected, true);
}

#[test]
fn native_selected_cached_kallsyms_policy_rejects_r() {
    selected_cache_policy("R", "poison", "_stext+0x10");
}

#[test]
fn native_selected_cached_kallsyms_policy_rejects_a() {
    selected_cache_policy("A", "poison", "_stext+0x10");
}

#[test]
fn native_selected_cached_kallsyms_policy_rejects_dollar() {
    selected_cache_policy("T", "$poison", "_stext+0x10");
}

#[test]
fn native_selected_cached_kallsyms_policy_accepts_d() {
    selected_cache_policy("D", "accepted", "accepted+0x8");
}

fn physical_lf_case(prefix: &str) {
    let rows = format!(
        "{prefix}ffffffff81000000 T _stext\nffffffff82000000 T _stext\nffffffff81000010 T wrong_target\nffffffff82000010 T native_target\nffffffff82002000 T tail\n"
    );
    super::assert_native_cached_kallsyms_reference(&rows, false, Some("native_target"));
}

#[test]
fn native_physical_reference_blank_consumes_next() {
    physical_lf_case("\n");
}

#[test]
fn native_physical_reference_hex_lf_consumes_next() {
    physical_lf_case("ffffffff81000080\n");
}

#[test]
fn native_physical_reference_separator_lf_consumes_next() {
    physical_lf_case("ffffffff81000080 T\n");
}

#[test]
fn native_physical_reference_type_lf_consumes_next() {
    physical_lf_case("ffffffff81000080 \n");
}
