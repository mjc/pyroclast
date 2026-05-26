use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use object::{Object, ObjectSymbol};
use pyroclast::cli::SymbolizerKind;
use pyroclast::perfdata::mappings::FileIdentity;
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};
use pyroclast::symbols::{
    Addr2lineResolver, Kallsyms, RustAddr2lineResolver, SymbolCache, SymbolRequest, SymbolResolver,
    perf_debug_dir, perf_dwarf_function_name, perf_inline_frame_order, perf_symbol_name,
    perf_symbol_resolver_for_perfdata_file, perf_symbol_resolver_for_perfdata_file_with_symbolizer,
};

#[test]
fn resolves_each_unique_symbol_address_once() {
    let resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);
    let mut cache = SymbolCache::new(&resolver);

    let first = cache
        .resolve(&SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        })
        .expect("first symbol");
    let second = cache
        .resolve(&SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        })
        .expect("second symbol");

    assert_eq!(first.as_deref(), Some("app::main"));
    assert_eq!(second.as_deref(), Some("app::main"));
    assert_eq!(
        resolver.batch_calls(),
        vec![vec![SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn symbol_resolver_frame_batch_defaults_to_single_symbol_frames() {
    let resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);

    let frames = resolver
        .resolve_frame_batch(&[SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("frames");

    assert_eq!(frames, vec![vec!["app::main".to_string()]]);
}

#[test]
fn batches_only_uncached_symbol_addresses() {
    let resolver = RecordingResolver::with_symbols([
        (
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            "app::main".to_string(),
        ),
        (
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            "app::work".to_string(),
        ),
    ]);
    let mut cache = SymbolCache::new(&resolver);
    cache
        .resolve_many(&[SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("prime cache");

    let symbols = cache
        .resolve_many(&[
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
        ])
        .expect("symbols");

    assert_eq!(
        symbols,
        vec![
            Some("app::main".to_string()),
            Some("app::work".to_string()),
            Some("app::work".to_string()),
        ]
    );
    assert_eq!(
        resolver.batch_calls(),
        vec![
            vec![SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }],
            vec![SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }],
        ]
    );
}

#[test]
fn addr2line_resolver_batches_requests_by_binary() {
    let runner = Addr2lineRunner::new(b"app::main\n/bin/app.rs:10\napp::work\n/bin/app.rs:20\n");
    let resolver = Addr2lineResolver::new(&runner);

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
        ])
        .expect("symbols");

    assert_eq!(
        symbols,
        vec![Some("app::main".to_string()), Some("app::work".to_string())]
    );
    assert_eq!(runner.commands().len(), 1);
    assert_eq!(
        runner.commands()[0].stdin.as_deref(),
        Some(&b"0x10\n0x20\n"[..])
    );
}

#[test]
fn rust_addr2line_resolver_reads_symbol_table_names() {
    let current_exe = std::env::current_exe().expect("current exe");
    let bytes = std::fs::read(&current_exe).expect("current exe bytes");
    let object = object::File::parse(bytes.as_slice()).expect("object file");
    let symbol = object
        .symbols()
        .filter(|symbol| symbol.address() != 0)
        .find(|symbol| {
            symbol
                .name()
                .is_ok_and(|name| name.contains("rust_addr2line_resolver_reads_symbol_table_names"))
        })
        .expect("test symbol");
    let resolver = RustAddr2lineResolver::new();

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: current_exe,
            relative_address: symbol.address(),
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    let symbol_name = symbols[0].as_deref().expect("symbol name");
    assert!(!symbol_name.is_empty());
}

#[test]
fn symbolizer_selector_can_use_rust_addr2line_without_process_runner() {
    let current_exe = std::env::current_exe().expect("current exe");
    let object_bytes = std::fs::read(&current_exe).expect("current exe bytes");
    let object = object::File::parse(object_bytes.as_slice()).expect("current exe object");
    let symbol = object
        .symbols()
        .filter(|symbol| symbol.address() != 0)
        .find(|symbol| {
            symbol
                .name()
                .is_ok_and(|name| name.contains("symbolizer_selector_can_use_rust_addr2line"))
        })
        .expect("test symbol");
    let runner = Addr2lineRunner::new(b"");
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    let resolver = perf_symbol_resolver_for_perfdata_file_with_symbolizer(
        &runner,
        &perfdata,
        home.path(),
        SymbolizerKind::RustAddr2line,
    );

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: current_exe,
            relative_address: symbol.address(),
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    let symbol_name = symbols[0].as_deref().expect("symbol name");
    assert!(!symbol_name.is_empty());
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_name_preserves_language_qualified_names_like_perf_script() {
    assert_eq!(
        perf_symbol_name("pyroclast::perfdata::attrs::parse_file_attrs"),
        "pyroclast::perfdata::attrs::parse_file_attrs"
    );
    assert_eq!(
        perf_symbol_name("<pyroclast::cli::RunArgs as clap_builder::derive::Args>::augment_args"),
        "<pyroclast::cli::RunArgs as clap_builder::derive::Args>::augment_args"
    );
    assert_eq!(
        perf_symbol_name("next<core::slice::iter::Iter<clap_builder::util::id::Id>>"),
        "next<core::slice::iter::Iter<clap_builder::util::id::Id>>"
    );
    assert_eq!(
        perf_symbol_name(
            "clone<(clap_builder::builder::arg_predicate::ArgPredicate, clap_builder::util::id::Id), alloc::alloc::Global>"
        ),
        "clone<(clap_builder::builder::arg_predicate::ArgPredicate, clap_builder::util::id::Id), alloc::alloc::Global>"
    );
    assert_eq!(
        perf_symbol_name("std::vector<int, std::allocator<int>>::push_back"),
        "std::vector<int, std::allocator<int>>::push_back"
    );
    assert_eq!(
        perf_symbol_name("foo::bar<std::vector<int>>::baz"),
        "foo::bar<std::vector<int>>::baz"
    );
    assert_eq!(
        perf_symbol_name("operator new(unsigned long)"),
        "operator new(unsigned long)"
    );
    assert_eq!(
        perf_symbol_name("__memmove_avx_unaligned_erms"),
        "__memmove_avx_unaligned_erms"
    );
}

#[test]
fn perf_dwarf_function_name_matches_perf_script_inline_names() {
    assert_eq!(
        perf_dwarf_function_name("pyroclast::perfdata::attrs::parse_file_attrs"),
        "parse_file_attrs"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "pyroclast::symbols::PerfSymbolResolver<O>::with_perfdata_file_kernel_cache"
        ),
        "with_perfdata_file_kernel_cache"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "<pyroclast::cli::RunArgs as clap_builder::derive::Args>::augment_args"
        ),
        "augment_args"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "insert_recursing<u64, alloc::string::String, alloc::alloc::Global, alloc::collections::btree::map::entry::{impl#8}::insert_entry::{closure_env#0}<u64, alloc::string::String, alloc::alloc::Global>>"
        ),
        "insert_recursing<u64, alloc::string::String, alloc::alloc::Global, alloc::collections::btree::map::entry::{impl#8}::insert_entry::{closure_env#0}<u64, alloc::string::String, alloc::alloc::Global>>"
    );
    assert_eq!(
        perf_dwarf_function_name("std::vector<int, std::allocator<int>>::push_back"),
        "std::vector<int, std::allocator<int>>::push_back"
    );
    assert_eq!(
        perf_dwarf_function_name("foo::bar<std::vector<int>>::baz"),
        "foo::bar<std::vector<int>>::baz"
    );
}

#[test]
fn perf_inline_frame_order_matches_perf_script_root_to_leaf() {
    assert_eq!(
        perf_inline_frame_order(vec!["value_name".to_string(), "augment_args".to_string()]),
        vec!["augment_args".to_string(), "value_name".to_string()]
    );
}

#[test]
fn addr2line_resolver_treats_failed_batches_as_unresolved() {
    let runner = Addr2lineRunner::failed();
    let resolver = Addr2lineResolver::new(&runner);

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
        ])
        .expect("failed addr2line should degrade");

    assert_eq!(symbols, vec![None, None]);
    assert_eq!(runner.commands().len(), 1);
}

#[test]
fn kallsyms_resolves_nearest_lower_kernel_symbol() {
    let symbols = Kallsyms::parse(
        "\
ffffffff88000000 T startup_64
ffffffff88000080 t asm_exc_page_fault
ffffffff88000100 T exc_page_fault
",
    )
    .expect("kallsyms");

    assert_eq!(
        symbols.resolve(0xffff_ffff_8800_008f).as_deref(),
        Some("asm_exc_page_fault")
    );
    assert_eq!(symbols.resolve(0xffff_ffff_87ff_ffff), None);
}

#[test]
fn kallsyms_ignores_malformed_lines() {
    let symbols = Kallsyms::parse(
        "\
not an address T nope
ffffffff88000080 t asm_exc_page_fault
",
    )
    .expect("kallsyms");

    assert_eq!(
        symbols.resolve(0xffff_ffff_8800_0080).as_deref(),
        Some("asm_exc_page_fault")
    );
}

#[test]
fn kallsyms_parses_system_map_lines() {
    let symbols = Kallsyms::parse(
        "\
ffffffff81001280 T asm_exc_page_fault
ffffffff812f5920 t do_user_addr_fault
",
    )
    .expect("system map");

    assert_eq!(
        symbols.resolve(0xffff_ffff_8100_1280).as_deref(),
        Some("asm_exc_page_fault")
    );
}

#[test]
fn kallsyms_resolves_relocated_kernel_addresses() {
    let symbols = Kallsyms::parse(
        "\
ffffffff81000000 T _text
ffffffff81001280 T asm_exc_page_fault
ffffffff82000000 T later_kernel_symbol
",
    )
    .expect("system map");

    assert_eq!(
        symbols
            .resolve_relocated(0xffff_ffff_8800_1280, "_text", 0xffff_ffff_8800_0000,)
            .as_deref(),
        Some("asm_exc_page_fault")
    );
}

#[test]
fn kallsyms_relocation_keeps_duplicate_address_aliases() {
    let symbols = Kallsyms::parse(
        "\
ffffffff81000000 T __pi__text
ffffffff81000000 T _stext
ffffffff81000000 T _text
ffffffff81000000 T srso_alias_untrain_ret
ffffffff81001280 T asm_exc_page_fault
",
    )
    .expect("system map");

    assert_eq!(
        symbols
            .resolve_relocated(0xffff_ffff_8800_1280, "_text", 0xffff_ffff_8800_0000,)
            .as_deref(),
        Some("asm_exc_page_fault")
    );
}

#[test]
fn kallsyms_rejects_address_masked_tables() {
    let result = Kallsyms::parse(
        "\
0000000000000000 T _stext
0000000000000000 T asm_exc_page_fault
",
    );

    assert!(result.is_err());
}

#[test]
fn kallsyms_loads_perf_build_id_cache_layout() {
    let root = tempfile::tempdir().expect("tempdir");
    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let cached = root
        .path()
        .join("[kernel.kallsyms]")
        .join(build_id)
        .join("kallsyms");
    std::fs::create_dir_all(cached.parent().expect("parent")).expect("cache dir");
    std::fs::write(&cached, "ffffffff88000080 t asm_exc_page_fault\n").expect("kallsyms");

    let symbols = Kallsyms::load_perf_build_id_cache(root.path(), build_id).expect("cache");

    assert_eq!(
        symbols.resolve(0xffff_ffff_8800_008f).as_deref(),
        Some("asm_exc_page_fault")
    );
}

#[test]
fn kallsyms_loads_old_perf_build_id_cache_layout() {
    let root = tempfile::tempdir().expect("tempdir");
    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let cached = root.path().join("[kernel.kallsyms]").join(build_id);
    std::fs::create_dir_all(cached.parent().expect("parent")).expect("cache dir");
    std::fs::write(&cached, "ffffffff88000080 t asm_exc_page_fault\n").expect("kallsyms");

    let symbols = Kallsyms::load_perf_build_id_cache(root.path(), build_id).expect("cache");

    assert_eq!(
        symbols.resolve(0xffff_ffff_8800_008f).as_deref(),
        Some("asm_exc_page_fault")
    );
}

#[test]
fn kallsyms_loads_first_parseable_system_map_candidate() {
    let root = tempfile::tempdir().expect("tempdir");
    let masked = root.path().join("masked.map");
    let valid = root.path().join("System.map");
    std::fs::write(&masked, "0000000000000000 T masked\n").expect("masked map");
    std::fs::write(&valid, "ffffffff81001280 T asm_exc_page_fault\n").expect("system map");

    let symbols = Kallsyms::load_first_system_map_candidate([masked, valid]).expect("system map");

    assert_eq!(
        symbols.resolve(0xffff_ffff_8100_1280).as_deref(),
        Some("asm_exc_page_fault")
    );
}

#[test]
fn perf_symbol_resolver_routes_kernel_requests_to_kallsyms() {
    let runner = Addr2lineRunner::new(b"app::main\n/bin/app.rs:10\n");
    let kallsyms = Kallsyms::parse(
        "\
ffffffff88000080 t asm_exc_page_fault
",
    )
    .expect("kallsyms");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner).with_kallsyms(kallsyms);

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                path: PathBuf::from("[kernel.kallsyms]"),
                relative_address: 0xffff_ffff_8800_008f,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
        ])
        .expect("symbols");

    assert_eq!(
        symbols,
        vec![
            Some("asm_exc_page_fault".to_string()),
            Some("app::main".to_string())
        ]
    );
    assert_eq!(runner.commands().len(), 1);
    assert_eq!(runner.commands()[0].stdin.as_deref(), Some(&b"0x10\n"[..]));
}

#[test]
fn perf_symbol_resolver_prefers_live_kallsyms_for_kernel_module_paths() {
    let cached =
        Kallsyms::parse("ffffffff8501cd2c R xen_elfnote_phys32_entry\n").expect("cached kallsyms");
    let live = Kallsyms::parse(
        "ffffffff8501cd2c R xen_elfnote_phys32_entry\n\
         ffffffffc0e66100 t zpl_iter_read\t[zfs]\n",
    )
    .expect("live kallsyms");
    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_kallsyms(cached)
        .with_live_kallsyms(live);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[zfs]"),
            relative_address: 0xffff_ffff_c0e6_61e9,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("zpl_iter_read".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_applies_kernel_relocation_to_kallsyms() {
    let runner = Addr2lineRunner::new(b"");
    let kallsyms = Kallsyms::parse(
        "\
ffffffff81000000 T _text
ffffffff81001280 T asm_exc_page_fault
ffffffff82000000 T later_kernel_symbol
",
    )
    .expect("system map");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner).with_kallsyms(kallsyms);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]_text"),
            relative_address: 0xffff_ffff_8800_1280,
            build_id: None,
            file_identity: None,
            kernel_relocation: Some(pyroclast::symbols::KernelRelocation {
                reference_symbol: "_text".to_string(),
                recorded_reference_address: 0xffff_ffff_8800_0000,
            }),
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("asm_exc_page_fault".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_loads_perfdata_kernel_build_id_cache() {
    let root = tempfile::tempdir().expect("tempdir");
    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let cached = root
        .path()
        .join("[kernel.kallsyms]")
        .join(build_id)
        .join("kallsyms");
    std::fs::create_dir_all(cached.parent().expect("parent")).expect("cache dir");
    std::fs::write(&cached, "ffffffff88000080 t asm_exc_page_fault\n").expect("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_perfdata_kernel_cache(&perfdata_with_kernel_build_id(), root.path());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: 0xffff_ffff_8800_008f,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("asm_exc_page_fault".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_loads_perfdata_kernel_build_id_cache_from_file() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");

    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let cached = root
        .path()
        .join("[kernel.kallsyms]")
        .join(build_id)
        .join("kallsyms");
    std::fs::create_dir_all(cached.parent().expect("parent")).expect("cache dir");
    std::fs::write(&cached, "ffffffff88000080 t asm_exc_page_fault\n").expect("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_perfdata_file_kernel_cache(&perfdata, root.path());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: 0xffff_ffff_8800_008f,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("asm_exc_page_fault".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_debug_dir_uses_home_debug_cache() {
    assert_eq!(
        perf_debug_dir(&PathBuf::from("/home/mjc")),
        PathBuf::from("/home/mjc/.debug")
    );
}

#[test]
fn perf_build_id_elf_path_uses_standard_cache_link_layout() {
    assert_eq!(
        pyroclast::symbols::perf_build_id_elf_path(
            &PathBuf::from("/home/mjc/.debug"),
            "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949",
        ),
        PathBuf::from("/home/mjc/.debug/.build-id/16/ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949/elf")
    );
}

#[test]
fn nixos_system_map_path_sits_next_to_kernel_image_symlink_target() {
    let root = tempfile::tempdir().expect("tempdir");
    let kernel_dir = root.path().join("nix/store/example-linux-6.18.32");
    std::fs::create_dir_all(&kernel_dir).expect("kernel dir");
    let kernel = kernel_dir.join("bzImage");
    std::fs::write(&kernel, b"kernel").expect("kernel image");
    let system_map = kernel_dir.join("System.map");
    std::fs::write(&system_map, "ffffffff81001280 T asm_exc_page_fault\n").expect("system map");

    assert_eq!(
        pyroclast::symbols::nixos_system_map_path(&kernel),
        Some(system_map)
    );
}

#[test]
fn linux_system_map_candidates_include_common_distribution_paths() {
    let candidates = pyroclast::symbols::linux_system_map_candidates(
        Some(&PathBuf::from("/nix/store/example-linux/bzImage")),
        "6.18.32",
    );

    assert_eq!(
        candidates,
        vec![
            PathBuf::from("/nix/store/example-linux/System.map"),
            PathBuf::from("/boot/System.map-6.18.32"),
            PathBuf::from("/usr/lib/debug/boot/System.map-6.18.32"),
            PathBuf::from("/lib/modules/6.18.32/System.map"),
            PathBuf::from("/usr/lib/debug/lib/modules/6.18.32/System.map"),
        ]
    );
}

#[test]
fn linux_system_map_candidates_for_system_deduplicates_kernel_images() {
    let candidates = pyroclast::symbols::linux_system_map_candidates_for_system(
        [
            PathBuf::from("/nix/store/example-linux/bzImage"),
            PathBuf::from("/nix/store/example-linux/bzImage"),
        ],
        "6.18.32",
    );

    assert_eq!(
        candidates,
        vec![
            PathBuf::from("/nix/store/example-linux/System.map"),
            PathBuf::from("/boot/System.map-6.18.32"),
            PathBuf::from("/usr/lib/debug/boot/System.map-6.18.32"),
            PathBuf::from("/lib/modules/6.18.32/System.map"),
            PathBuf::from("/usr/lib/debug/lib/modules/6.18.32/System.map"),
        ]
    );
}

#[test]
fn perf_symbol_resolver_constructor_uses_perfdata_cache_before_system_kallsyms() {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");

    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let cached = home
        .path()
        .join(".debug")
        .join("[kernel.kallsyms]")
        .join(build_id)
        .join("kallsyms");
    std::fs::create_dir_all(cached.parent().expect("parent")).expect("cache dir");
    std::fs::write(&cached, "ffffffff88000080 t cached_kernel_symbol\n").expect("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = perf_symbol_resolver_for_perfdata_file(&runner, &perfdata, home.path());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: 0xffff_ffff_8800_008f,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("cached_kernel_symbol".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_prefers_perfdata_kallsyms_over_kernel_elf() {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");

    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let cached = home
        .path()
        .join(".debug")
        .join("[kernel.kallsyms]")
        .join(build_id)
        .join("kallsyms");
    std::fs::create_dir_all(cached.parent().expect("parent")).expect("cache dir");
    std::fs::write(&cached, "ffffffff88000080 t __pi_memcpy\n").expect("kallsyms");
    let kernel_elf =
        pyroclast::symbols::perf_build_id_elf_path(&perf_debug_dir(home.path()), build_id);
    std::fs::create_dir_all(kernel_elf.parent().expect("kernel elf parent")).expect("cache dir");
    std::fs::write(&kernel_elf, b"not a real elf; runner is faked").expect("kernel elf");

    let runner = Addr2lineRunner::new(b"memcpy\n??:0\n");
    let resolver = perf_symbol_resolver_for_perfdata_file(&runner, &perfdata, home.path());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: 0xffff_ffff_8800_008f,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("__pi_memcpy".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_uses_kernel_build_id_elf_when_kallsyms_is_missing() {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");

    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let kernel_elf =
        pyroclast::symbols::perf_build_id_elf_path(&perf_debug_dir(home.path()), build_id);
    std::fs::create_dir_all(kernel_elf.parent().expect("kernel elf parent")).expect("cache dir");
    std::fs::write(&kernel_elf, b"not a real elf; runner is faked").expect("kernel elf");

    let runner = Addr2lineRunner::new(b"asm_exc_page_fault\n??:0\n");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_perfdata_file_kernel_cache(&perfdata, &perf_debug_dir(home.path()));

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: 0xffff_ffff_8800_008f,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("asm_exc_page_fault".to_string())]);
    assert_eq!(
        runner.commands()[0].args,
        vec![
            "-f".to_string(),
            "-C".to_string(),
            "-e".to_string(),
            kernel_elf.display().to_string(),
        ]
    );
}

#[test]
fn perf_symbol_resolver_prefers_system_kallsyms_over_kernel_elf() {
    let root = tempfile::tempdir().expect("root");
    let kernel_elf = root.path().join("vmlinux");
    std::fs::write(&kernel_elf, b"not a real elf; runner is faked").expect("kernel elf");
    let kallsyms = root.path().join("kallsyms");
    std::fs::write(
        &kallsyms,
        "\
ffffffff846997a0 T memcpy
ffffffff846997a0 T __memcpy
ffffffff846997a0 T __pi_memcpy
",
    )
    .expect("kallsyms");

    let runner = Addr2lineRunner::new(b"memcpy\n??:0\n");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_kernel_elf(kernel_elf)
        .with_system_kallsyms_from_path(&kallsyms);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: 0xffff_ffff_8469_97ac,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("__pi_memcpy".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_uses_module_build_id_elf() {
    let home = tempfile::tempdir().expect("home");
    let build_id = "d6ed2003b20b59c61cdc649124d920215521fc00";
    let module_elf =
        pyroclast::symbols::perf_build_id_elf_path(&perf_debug_dir(home.path()), build_id);
    std::fs::create_dir_all(module_elf.parent().expect("module elf parent")).expect("cache dir");
    std::fs::write(&module_elf, b"not a real elf; runner is faked").expect("module elf");

    let runner = Addr2lineRunner::new(b"igb_clean_rx_irq\n??:0\n");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_debug_dir(perf_debug_dir(home.path()));

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[igb]"),
            relative_address: 0x30,
            build_id: Some(build_id.to_string()),
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("igb_clean_rx_irq".to_string())]);
    assert_eq!(
        runner.commands()[0].args,
        vec![
            "-f".to_string(),
            "-C".to_string(),
            "-e".to_string(),
            module_elf.display().to_string(),
        ]
    );
}

#[test]
fn perf_symbol_resolver_accepts_pluggable_object_resolver() {
    let object_resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(object_resolver);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("app::main".to_string())]);
    assert_eq!(
        resolver.object_resolver().batch_calls(),
        vec![vec![SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn perf_symbol_resolver_preserves_pluggable_object_frame_lists() {
    let object_resolver = RecordingResolver::with_frames([(
        SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        vec!["app::outer".to_string(), "app::inner".to_string()],
    )]);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(object_resolver);

    let frames = resolver
        .resolve_frame_batch(&[SymbolRequest {
            path: PathBuf::from("/bin/app"),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("frames");

    assert_eq!(
        frames,
        vec![vec!["app::outer".to_string(), "app::inner".to_string()]]
    );
}

#[test]
fn perf_symbol_resolver_skips_stale_user_objects() {
    let object_path = tempfile::NamedTempFile::new().expect("object file");
    let object_resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            path: object_path.path().to_path_buf(),
            relative_address: 0x10,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(object_resolver);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: object_path.path().to_path_buf(),
            relative_address: 0x10,
            build_id: None,
            file_identity: Some(FileIdentity {
                major: 0,
                minor: 0,
                inode: u64::MAX,
                inode_generation: 0,
            }),
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![None]);
    assert_eq!(
        resolver.object_resolver().batch_calls(),
        Vec::<Vec<SymbolRequest>>::new()
    );
}

#[test]
fn perf_symbol_resolver_uses_system_map_candidates_when_cache_is_missing() {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");
    let system_map = home.path().join("System.map");
    std::fs::write(&system_map, "ffffffff81001280 T asm_exc_page_fault\n").expect("system map");

    let runner = Addr2lineRunner::new(b"");
    let resolver = perf_symbol_resolver_for_perfdata_file(&runner, &perfdata, home.path())
        .with_system_map_candidates([system_map]);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]_text"),
            relative_address: 0xffff_ffff_8100_1280,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("asm_exc_page_fault".to_string())]);
    assert!(runner.commands().is_empty());
}

#[derive(Default)]
struct RecordingResolver {
    symbols: BTreeMap<SymbolRequest, String>,
    frames: BTreeMap<SymbolRequest, Vec<String>>,
    calls: RefCell<Vec<Vec<SymbolRequest>>>,
}

fn perfdata_with_kernel_build_id() -> Vec<u8> {
    let build_id = [
        0x16, 0xed, 0x3d, 0x53, 0x17, 0xad, 0x21, 0x9c, 0x89, 0xd0, 0xe3, 0xc5, 0xea, 0x0e, 0xa2,
        0xca, 0xa3, 0xcd, 0x49, 0x49,
    ];
    let payload = build_id_event_payload(u32::MAX, &build_id, "[kernel.kallsyms]");
    perfdata_with_build_id_feature(&payload)
}

fn build_id_event_payload(pid: u32, build_id: &[u8; 20], filename: &str) -> Vec<u8> {
    let size = 36 + filename.len() + 1;
    let mut payload = Vec::new();
    payload.extend(67_u32.to_le_bytes());
    payload.extend(0_u16.to_le_bytes());
    payload.extend(u16::try_from(size).expect("event size").to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(build_id);
    payload.extend([0; 4]);
    payload.extend(filename.as_bytes());
    payload.push(0);
    payload
}

fn perfdata_with_build_id_feature(payload: &[u8]) -> Vec<u8> {
    let feature_table_offset = 128;
    let payload_offset = 160;
    let mut bytes = vec![0; payload_offset + payload.len()];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 40, 128);
    put_u64(&mut bytes, 48, 0);
    put_u64(&mut bytes, 56, 1 << 2);
    put_u64(&mut bytes, feature_table_offset, payload_offset as u64);
    put_u64(
        &mut bytes,
        feature_table_offset + 8,
        u64::try_from(payload.len()).expect("payload size"),
    );
    bytes[payload_offset..].copy_from_slice(payload);
    bytes
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

impl RecordingResolver {
    fn with_symbols<const N: usize>(symbols: [(SymbolRequest, String); N]) -> Self {
        Self {
            symbols: symbols.into(),
            frames: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn with_frames<const N: usize>(frames: [(SymbolRequest, Vec<String>); N]) -> Self {
        Self {
            symbols: BTreeMap::new(),
            frames: frames.into(),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn batch_calls(&self) -> Vec<Vec<SymbolRequest>> {
        self.calls.borrow().clone()
    }
}

impl SymbolResolver for RecordingResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.calls.borrow_mut().push(requests.to_vec());
        Ok(requests
            .iter()
            .map(|request| self.symbols.get(request).cloned())
            .collect())
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        if self.frames.is_empty() {
            return self.resolve_batch(requests).map(|symbols| {
                symbols
                    .into_iter()
                    .map(|symbol| symbol.into_iter().collect())
                    .collect()
            });
        }
        self.calls.borrow_mut().push(requests.to_vec());
        Ok(requests
            .iter()
            .map(|request| self.frames.get(request).cloned().unwrap_or_default())
            .collect())
    }
}

struct Addr2lineRunner {
    status_code: Option<i32>,
    stdout: Vec<u8>,
    commands: Mutex<Vec<CommandSpec>>,
}

impl Addr2lineRunner {
    fn new(stdout: &[u8]) -> Self {
        Self {
            status_code: Some(0),
            stdout: stdout.to_vec(),
            commands: Mutex::new(Vec::new()),
        }
    }

    fn failed() -> Self {
        Self {
            status_code: Some(1),
            stdout: Vec::new(),
            commands: Mutex::new(Vec::new()),
        }
    }

    fn commands(&self) -> Vec<CommandSpec> {
        self.commands.lock().unwrap().clone()
    }
}

impl CommandRunner for Addr2lineRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        Ok(CommandOutput {
            status_code: self.status_code,
            stdout: self.stdout.clone(),
            stderr: Vec::new(),
        })
    }
}
