use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SymbolKind, build, elf};
use proptest::prelude::*;
use pyroclast::cli::SymbolizerKind;
use pyroclast::perfdata::mappings::FileIdentity;
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};
use pyroclast::symbols::{
    Addr2lineResolver, Kallsyms, RustAddr2lineResolver, SymbolCache, SymbolRequest, SymbolResolver,
    perf_build_id_elf_path_for_dso, perf_debug_dir, perf_dwarf_frame_names_from_object,
    perf_dwarf_frame_names_from_object_bytes, perf_dwarf_function_name, perf_inline_frame_order,
    perf_symbol_name, perf_symbol_resolver_for_perfdata_file,
    perf_symbol_resolver_for_perfdata_file_with_object,
    perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources,
    perf_symbol_resolver_for_perfdata_file_with_symbolizer,
};

fn test_symbol_request(path_index: u8, relative_address: u16) -> SymbolRequest {
    SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: PathBuf::from(format!("/bin/app{}", path_index % 4)),
        relative_address: u64::from(relative_address),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    }
}

fn test_symbol_name(request: &SymbolRequest) -> String {
    format!("{}::{:x}", request.path.display(), request.relative_address)
}

fn expected_unique_requests(requests: &[SymbolRequest]) -> Vec<SymbolRequest> {
    let mut unique = Vec::new();
    for request in requests {
        if !unique.contains(request) {
            unique.push(request.clone());
        }
    }
    unique
}

fn recording_resolver_for(requests: &[SymbolRequest]) -> RecordingResolver {
    let symbols = expected_unique_requests(requests)
        .into_iter()
        .map(|request| {
            let symbol = test_symbol_name(&request);
            (request, symbol)
        })
        .collect();
    RecordingResolver {
        symbols,
        frames: BTreeMap::new(),
        calls: RefCell::new(Vec::new()),
    }
}

#[derive(Clone, Debug)]
struct KallsymsResolveCase {
    text: String,
    query: u64,
    expected: String,
}

fn kallsyms_resolve_case() -> impl Strategy<Value = KallsymsResolveCase> {
    prop::collection::vec(any::<u8>(), 1..20)
        .prop_flat_map(|offsets| {
            let len = offsets.len();
            (Just(offsets), 0..len, 0_u64..0x800)
        })
        .prop_map(|(offsets, index, delta)| {
            const BASE: u64 = 0xffff_ffff_8800_0000;

            let addresses = offsets
                .iter()
                .enumerate()
                .map(|(position, offset)| BASE + (position as u64) * 0x1000 + u64::from(*offset))
                .collect::<Vec<_>>();
            let text = addresses.iter().enumerate().fold(
                String::new(),
                |mut text, (position, address)| {
                    let _ = writeln!(text, "{address:016x} T symbol_{position}");
                    text
                },
            );

            KallsymsResolveCase {
                text,
                query: addresses[index] + delta,
                expected: format!("symbol_{index}"),
            }
        })
}

#[test]
fn resolves_each_unique_symbol_address_once() {
    let resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);
    let mut cache = SymbolCache::new(&resolver);

    let first = cache
        .resolve(&SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        })
        .expect("first symbol");
    let second = cache
        .resolve(&SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
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
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
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
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);

    let frames = resolver
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("frames");

    assert_eq!(frames, vec![vec!["app::main".to_string()]]);
}

#[test]
fn batches_only_uncached_symbol_addresses() {
    let request = |relative_address| SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: PathBuf::from("/bin/app"),
        relative_address,
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let resolver = RecordingResolver::with_symbols([
        (request(0x10), "app::main".to_string()),
        (request(0x20), "app::work".to_string()),
    ]);
    let mut cache = SymbolCache::new(&resolver);
    cache.resolve_many(&[request(0x10)]).expect("prime cache");

    let symbols = cache
        .resolve_many(&[request(0x10), request(0x20), request(0x20)])
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
        vec![vec![request(0x10)], vec![request(0x20)]]
    );
}

proptest! {
    #[test]
    fn property_symbol_cache_batches_first_seen_unique_requests(
        specs in prop::collection::vec((0_u8..8, any::<u16>()), 0..40),
    ) {
        let requests = specs
            .into_iter()
            .map(|(path_index, relative_address)| test_symbol_request(path_index, relative_address))
            .collect::<Vec<_>>();
        let resolver = recording_resolver_for(&requests);
        let mut cache = SymbolCache::new(&resolver);

        let symbols = cache.resolve_many(&requests).expect("symbols");

        let expected_symbols = requests
            .iter()
            .map(|request| Some(test_symbol_name(request)))
            .collect::<Vec<_>>();
        prop_assert_eq!(symbols, expected_symbols);

        let expected_calls = expected_unique_requests(&requests);
        let expected_batches = if expected_calls.is_empty() {
            Vec::new()
        } else {
            vec![expected_calls]
        };
        prop_assert_eq!(resolver.batch_calls(), expected_batches);
    }

    #[test]
    fn property_symbol_cache_only_batches_new_misses_after_priming(
        first_specs in prop::collection::vec((0_u8..8, any::<u16>()), 0..24),
        second_specs in prop::collection::vec((0_u8..8, any::<u16>()), 0..24),
    ) {
        let first_requests = first_specs
            .into_iter()
            .map(|(path_index, relative_address)| test_symbol_request(path_index, relative_address))
            .collect::<Vec<_>>();
        let second_requests = second_specs
            .into_iter()
            .map(|(path_index, relative_address)| test_symbol_request(path_index, relative_address))
            .collect::<Vec<_>>();
        let mut all_requests = first_requests.clone();
        all_requests.extend(second_requests.iter().cloned());

        let resolver = recording_resolver_for(&all_requests);
        let mut cache = SymbolCache::new(&resolver);

        let primed = cache.resolve_many(&first_requests).expect("primed");
        let resolved = cache.resolve_many(&second_requests).expect("resolved");

        let expected_primed = first_requests
            .iter()
            .map(|request| Some(test_symbol_name(request)))
            .collect::<Vec<_>>();
        let expected_resolved = second_requests
            .iter()
            .map(|request| Some(test_symbol_name(request)))
            .collect::<Vec<_>>();
        prop_assert_eq!(primed, expected_primed);
        prop_assert_eq!(resolved, expected_resolved);

        let first_batch = expected_unique_requests(&first_requests);
        let second_batch = expected_unique_requests(&second_requests)
            .into_iter()
            .filter(|request| !first_batch.contains(request))
            .collect::<Vec<_>>();
        let mut expected_batches = Vec::new();
        if !first_batch.is_empty() {
            expected_batches.push(first_batch);
        }
        if !second_batch.is_empty() {
            expected_batches.push(second_batch);
        }
        prop_assert_eq!(resolver.batch_calls(), expected_batches);
    }

    #[test]
    fn property_kallsyms_resolves_nearest_lower_symbol(case in kallsyms_resolve_case()) {
        let symbols = Kallsyms::parse(&case.text).expect("kallsyms");

        prop_assert_eq!(symbols.resolve(case.query), Some(case.expected));
    }
}

#[test]
fn addr2line_resolver_batches_requests_by_binary() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("app");
    std::fs::write(&path, elf_with_dynamic_text_symbol(b"app", 0x1000, 46))
        .expect("write regular object");
    let runner = Addr2lineRunner::new(b"app::main\n/bin/app.rs:10\napp::work\n/bin/app.rs:20\n");
    let resolver = Addr2lineResolver::new(&runner);

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path: path.clone(),
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0x10,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path,
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0x20,
                kernel_mapping_range: None,
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
fn addr2line_resolver_does_not_spawn_for_missing_objects() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = Addr2lineRunner::new(b"phantom\n??:0\n");
    let resolver = Addr2lineResolver::new(&runner);
    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: root.path().join("missing-object"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("missing source is unresolved");
    assert_eq!(symbols, [None]);
    assert!(runner.commands().is_empty());
}

#[cfg(target_os = "linux")]
fn scalar_dual_address_fixture() -> (tempfile::NamedTempFile, SymbolRequest) {
    let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
    builder.header.e_type = elf::ET_EXEC;
    builder.header.e_machine = elf::EM_X86_64;
    let section = builder.sections.add();
    section.name = b".text"[..].into();
    section.sh_type = elf::SHT_PROGBITS;
    section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
    section.sh_addr = 0x1000;
    section.sh_offset = 0x1000;
    section.sh_addralign = 16;
    section.data = build::elf::SectionData::Data(vec![0xcc; 32].into());
    let text = section.id();
    for (name, address) in [
        (b"base_entry".as_slice(), 0x1000),
        (b"inline_entry", 0x1010),
    ] {
        let symbol = builder.symbols.add();
        symbol.name = name.into();
        symbol.st_value = address;
        symbol.st_size = 16;
        symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
        symbol.section = Some(text);
    }
    for (name, kind, data) in [
        (
            b".shstrtab".as_slice(),
            elf::SHT_STRTAB,
            build::elf::SectionData::SectionString,
        ),
        (b".symtab", elf::SHT_SYMTAB, build::elf::SectionData::Symbol),
        (b".strtab", elf::SHT_STRTAB, build::elf::SectionData::String),
    ] {
        let section = builder.sections.add();
        section.name = name.into();
        section.sh_type = kind;
        section.sh_addralign = if kind == elf::SHT_SYMTAB { 8 } else { 1 };
        section.data = data;
    }
    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    let native = Command::new("addr2line")
        .args(["-f", "-e"])
        .arg(file.path())
        .args(["0x1008", "0x1018"])
        .env("DEBUGINFOD_URLS", "")
        .output()
        .unwrap();
    assert!(native.status.success(), "{native:?}");
    let native = String::from_utf8(native.stdout).unwrap();
    assert_eq!(native.lines().count(), 4, "{native}");
    assert_eq!(
        native.lines().step_by(2).collect::<Vec<_>>(),
        ["base_entry", "inline_entry"]
    );
    let request = SymbolRequest {
        path: file.path().into(),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0x1008,
        addr2line_address: Some(0x1018),
        ..test_symbol_request(0, 0)
    };
    (file, request)
}

#[cfg(target_os = "linux")]
#[test]
fn scalar_resolvers_keep_base_vma_when_inline_query_resolves_another_symbol() {
    // perf event.c:machine__resolve uses the base symbol; only
    // machine.c:append_inlines passes map__rip_2objdump to libdw/addr2line.
    let (_file, request) = scalar_dual_address_fixture();
    let runner = pyroclast::process::RealCommandRunner::default();
    for kind in [SymbolizerKind::RustAddr2line, SymbolizerKind::Addr2line] {
        let resolver = pyroclast::symbols::SelectedObjectResolver::new(&runner, kind);
        assert_eq!(
            resolver
                .resolve_batch(std::slice::from_ref(&request))
                .unwrap(),
            [Some("base_entry".into())]
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn scalar_symbol_cache_keeps_base_vma_across_inline_overrides() {
    let (_file, request) = scalar_dual_address_fixture();
    let runner = pyroclast::process::RealCommandRunner::default();
    for kind in [SymbolizerKind::RustAddr2line, SymbolizerKind::Addr2line] {
        let resolver = pyroclast::symbols::SelectedObjectResolver::new(&runner, kind);
        let mut cache = SymbolCache::new(&resolver);
        for inline in [None, Some(0x1018), Some(0x1008), Some(0x1018)] {
            let request = SymbolRequest {
                addr2line_address: inline,
                ..request.clone()
            };
            assert_eq!(cache.resolve(&request).unwrap(), Some("base_entry".into()));
        }
    }
}

#[test]
fn addr2line_resolver_prefers_perf_object_alias_over_underscored_addr2line_name() {
    let root = tempfile::tempdir().expect("tempdir");
    let object_path = root.path().join("libc.so.6");
    std::fs::write(
        &object_path,
        elf_with_dynamic_text_symbol(b"read", 0x1000, 46),
    )
    .expect("write object");
    let runner = Addr2lineRunner::new(b"__libc_read\n??:0\n");
    let resolver = Addr2lineResolver::new(&runner);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: object_path,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x1008,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("read".to_string())]);
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
            addr2line_address: None,
            kernel_module_address: None,
            path: current_exe,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: symbol.address(),
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    let symbol_name = symbols[0].as_deref().expect("symbol name");
    assert!(!symbol_name.is_empty());
}

#[test]
fn rust_addr2line_resolver_preserves_qualified_symtab_name_like_perf() {
    // perf's event symbol path is machine__resolve() -> map__find_symbol();
    // Linux v7.2.9 tools/perf/util/libdw.c:99-108 obtains inline names from
    // integrated DW_AT_linkage_name, falling back to DW_AT_name. GNU
    // addr2line similarly prints the
    // functionname returned by bfd_find_nearest_line_discriminator(). None of
    // those paths scan unrelated .debug_str/object bytes to specialize a
    // symtab placeholder.
    let root = tempfile::tempdir().expect("tempdir");
    let object_path = root.path().join("libgeneric.so");
    let mut object_bytes = elf_with_dynamic_text_symbol(
        b"alloc::collections::btree::map::IntoIter<K,V,A>::dying_next",
        0x1000,
        0x200,
    );
    object_bytes.extend_from_slice(
        b"\0alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next\0",
    );
    std::fs::write(&object_path, object_bytes).expect("write object");
    let resolver = RustAddr2lineResolver::new();

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: object_path,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x1180,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(
        symbols,
        vec![Some(
            "alloc::collections::btree::map::IntoIter<K,V,A>::dying_next".to_string()
        )]
    );
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
            addr2line_address: None,
            kernel_module_address: None,
            path: current_exe,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: symbol.address(),
            kernel_mapping_range: None,
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
fn perf_symbol_name_preserves_demangled_symtab_names_like_perf_script() {
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
        perf_symbol_name(
            "alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next"
        ),
        "alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next"
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
fn perf_dwarf_function_name_preserves_unmangled_die_name_like_libdw() {
    // Linux v7.2.9 tools/perf/util/libdw.c:99-108 falls back to die_name()
    // without linkage; tools/perf/util/srcline.c:new_inline_sym demangles it.
    assert_eq!(
        perf_dwarf_function_name("pyroclast::perfdata::attrs::parse_file_attrs"),
        "pyroclast::perfdata::attrs::parse_file_attrs"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "pyroclast::symbols::PerfSymbolResolver<O>::with_perfdata_file_kernel_cache"
        ),
        "pyroclast::symbols::PerfSymbolResolver<O>::with_perfdata_file_kernel_cache"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "pyroclast::symbols::perf_symbol_resolver_for_current_home_with_symbolizer<pyroclast::process::RealCommandRunner>"
        ),
        "pyroclast::symbols::perf_symbol_resolver_for_current_home_with_symbolizer<pyroclast::process::RealCommandRunner>"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "<pyroclast::cli::RunArgs as clap_builder::derive::Args>::augment_args"
        ),
        "<pyroclast::cli::RunArgs as clap_builder::derive::Args>::augment_args"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "insert_recursing<u64, alloc::string::String, alloc::alloc::Global, alloc::collections::btree::map::entry::{impl#8}::insert_entry::{closure_env#0}<u64, alloc::string::String, alloc::alloc::Global>>"
        ),
        "insert_recursing<u64, alloc::string::String, alloc::alloc::Global, alloc::collections::btree::map::entry::{impl#8}::insert_entry::{closure_env#0}<u64, alloc::string::String, alloc::alloc::Global>>"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "alloc::collections::btree::map::BTreeMap<u64, alloc::string::String, alloc::alloc::Global>::insert"
        ),
        "alloc::collections::btree::map::BTreeMap<u64, alloc::string::String, alloc::alloc::Global>::insert"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next"
        ),
        "alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next"
    );
    assert_eq!(
        perf_dwarf_function_name("std::vector<int, std::allocator<int>>::push_back"),
        "std::vector<int, std::allocator<int>>::push_back"
    );
    assert_eq!(
        perf_dwarf_function_name("foo::bar<std::vector<int>>::baz"),
        "foo::bar<std::vector<int>>::baz"
    );
    assert_eq!(
        perf_dwarf_function_name("std::fs::read::inner"),
        "std::fs::read::inner"
    );
    assert_eq!(
        perf_dwarf_function_name("std::io::default_read_to_end::<std::fs::File>"),
        "std::io::default_read_to_end::<std::fs::File>"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "core::option::Option<alloc::string::String>::map_or_else<&str, alloc::string::String, alloc::fmt::format::{closure_env#0}, fn(&str) -> alloc::string::String>"
        ),
        "core::option::Option<alloc::string::String>::map_or_else<&str, alloc::string::String, alloc::fmt::format::{closure_env#0}, fn(&str) -> alloc::string::String>"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "aws_smithy_runtime_api::client::retries::classifiers::maybe_shared<aws_smithy_runtime_api::client::retries::classifiers::SharedRetryClassifier, aws_runtime::retries::classifiers::AwsErrorCodeClassifier<aws_sdk_s3::operation::put_object::PutObjectError>, fn(aws_runtime::retries::classifiers::AwsErrorCodeClassifier<aws_sdk_s3::operation::put_object::PutObjectError>) -> aws_smithy_runtime_api::client::retries::classifiers::SharedRetryClassifier>"
        ),
        "aws_smithy_runtime_api::client::retries::classifiers::maybe_shared<aws_smithy_runtime_api::client::retries::classifiers::SharedRetryClassifier, aws_runtime::retries::classifiers::AwsErrorCodeClassifier<aws_sdk_s3::operation::put_object::PutObjectError>, fn(aws_runtime::retries::classifiers::AwsErrorCodeClassifier<aws_sdk_s3::operation::put_object::PutObjectError>) -> aws_smithy_runtime_api::client::retries::classifiers::SharedRetryClassifier>"
    );
}

#[test]
fn perf_dwarf_frame_names_prefer_qualified_linkage_names_like_perf_script() {
    // Linux v7.2.9 tools/perf/util/libdw.c:99-108 prefers integrated
    // DW_AT_linkage_name, then new_inline_sym() demangles it. Rust inline
    // frames therefore retain their namespace/type qualification.
    let Some((profiling_binary, object_bytes)) = profiling_binary_fixture() else {
        return;
    };
    let Some(address) = generic_dwarf_name_candidate_addresses(&object_bytes)
        .into_iter()
        .find(|address| {
            let Some(frames) = perf_dwarf_frame_names_from_object_bytes(&object_bytes, *address)
            else {
                return false;
            };
            let Some(linkage_names) =
                external_addr2line_linkage_frames_root_to_leaf(&profiling_binary, *address)
            else {
                return false;
            };
            frames.len() == linkage_names.len()
                && frames != linkage_names
                && frames.iter().any(|frame| frame.contains('<'))
        })
    else {
        return;
    };

    let frames =
        perf_dwarf_frame_names_from_object(&profiling_binary, address).expect("perf dwarf frames");
    let linkage_names = external_addr2line_linkage_frames_root_to_leaf(&profiling_binary, address)
        .expect("linkage-name frames");

    assert_eq!(frames.len(), linkage_names.len());
    assert!(
        frames
            .iter()
            .any(|frame| frame.contains("::deallocating_next") || frame.contains("::dying_next")),
        "expected a qualified linkage name, got {frames:?}"
    );
    assert!(
        !frames.iter().any(
            |frame| frame.starts_with("deallocating_next<") || frame.starts_with("dying_next<")
        ),
        "unqualified DIE name leaked into linkage-style names: {frames:?}"
    );
}

#[test]
fn perf_dwarf_frame_names_can_use_existing_object_bytes() {
    let Some((profiling_binary, bytes)) = profiling_binary_fixture() else {
        return;
    };
    let Some(address) = find_profiling_address(&bytes, |frames| frames.len() > 1) else {
        return;
    };

    let frames =
        perf_dwarf_frame_names_from_object_bytes(&bytes, address).expect("perf dwarf frames");

    assert_eq!(
        frames,
        perf_dwarf_frame_names_from_object(&profiling_binary, address)
            .expect("path-backed perf dwarf frames")
    );
}

#[test]
#[cfg(target_os = "linux")]
fn perf_dwarf_frame_names_keep_fn0_die_name() {
    // Linux v7.2.9 tools/perf/util/libdw.c:85-108 keeps the ELF outer symbol
    // and otherwise uses linkage/name attributes in new_inline_sym(). The
    // zero-address sentinel in perf/util/addr2line.c is a child-process
    // protocol record, not a spelling rule for DW_AT_name.
    let (_root, binary, bytes) = compiled_c_fixture("int fn0(void) { return 7; }");
    let address = text_symbol_addresses_matching_name(&bytes, |name| name == "fn0")[0];
    assert_eq!(
        perf_dwarf_frame_names_from_object(&binary, address),
        Some(vec!["fn0".to_string()])
    );
}

#[test]
#[cfg(target_os = "linux")]
fn symbol_parity_source_lined_function_keeps_symtab_alias_without_inline_children() {
    // Linux v7.2.9 tools/perf/util/libdw.c:85-96 reuses args->sym for the
    // outer subprogram, even if its DWARF name differs from the ELF symbol.
    let (_root, binary, bytes) =
        compiled_c_fixture("void f(void) __asm__(\"float\"); void f(void) {}");
    let address = text_symbol_addresses_matching_name(&bytes, |name| name == "float")[0];

    assert_eq!(
        perf_dwarf_frame_names_from_object(&binary, address),
        Some(vec!["float".to_string()])
    );

    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: binary,
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: address,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let resolver = RustAddr2lineResolver::new();
    let frames = resolver
        .resolve_frame_batch_with_metadata(&[request])
        .unwrap();
    assert_eq!(frames[0].frames, ["float+0x0"]);
    assert!(!frames[0].has_inline_frames);
    assert!(frames[0].has_non_inline_base_frame);
    assert_eq!(frames[0].base_offset, Some(0));
}

#[test]
#[cfg(target_os = "linux")]
fn rust_addr2line_resolver_keeps_perf_symtab_alias_without_debug_line() {
    // perf/util/symbol.c choose_best_symbol() selects the longer alias.
    // perf/util/libdw.c requires a source line before it can emit inline
    // frames, and perf/util/addr2line.c:cmd__addr2line requires .debug_line
    // before starting its subprocess. Stripping debug info keeps the base.
    let (_root, binary, bytes) = compiled_c_fixture(
        "void short_name(void) {} void preferred_alias(void) __attribute__((alias(\"short_name\")));",
    );
    let address = text_symbol_addresses_matching_name(&bytes, |name| name == "preferred_alias")[0];
    let output = Command::new("objcopy")
        .arg("--strip-debug")
        .arg(&binary)
        .output()
        .expect("strip fixture debug info");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stripped = std::fs::read(&binary).expect("read stripped fixture");
    let object = object::File::parse(&stripped[..]).expect("parse stripped fixture");
    assert!(object.section_by_name(".debug_line").is_none());
    assert!(
        object
            .symbols()
            .all(|symbol| symbol.kind() != SymbolKind::File),
        "stripped fixture must have no STT_FILE records"
    );

    let frames = RustAddr2lineResolver::new()
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: binary,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve stripped alias");

    assert_eq!(frames, vec![vec!["preferred_alias+0x0".to_string()]]);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn compiled_bfd_zero_sized_alias_fixture() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    compiled_c_fixture(
        r#"
        int with_source_line(void) { return 7; }
        __asm__(
            ".pushsection .text.alias_fixture,\"ax\",@progbits\n"
            ".type local_function,@function\n"
            "local_function:\n"
            ".fill 16,1,0x90\n"
            ".size local_function,16\n"
            ".globl global_alias\n"
            ".type global_alias,@function\n"
            ".set global_alias,local_function\n"
            ".size global_alias,0\n"
            ".fill 16,1,0x90\n"
            ".globl next_function\n"
            ".type next_function,@function\n"
            "next_function:\n"
            ".fill 16,1,0x90\n"
            ".size next_function,16\n"
            ".popsection\n"
        );
        "#,
    )
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn rust_addr2line_bfd_fallback_uses_raw_zero_sized_alias_extent_like_binutils() {
    // addr2line.c:find_address_in_section calls BFD's nearest-line lookup.
    // bfd/elf.c:_bfd_elf_maybe_function_sym reads raw st_size, and
    // bfd/dwarf2.c:better_fit keeps the larger raw extent when neither alias
    // reaches the queried address. The C function supplies unrelated DWARF;
    // the assembly aliases have no source line, forcing function fallback.
    let (_root, binary, bytes) = compiled_bfd_zero_sized_alias_fixture();
    let object = object::File::parse(bytes.as_slice()).expect("fixture ELF");
    let local = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("local_function"))
        .expect("local function");
    let alias = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("global_alias"))
        .expect("global alias");
    assert_eq!(local.size(), 16);
    assert_eq!(alias.size(), 0);
    assert_eq!(alias.address(), local.address());
    let address = local.address() + 24;
    let native = Command::new("addr2line")
        .args(["-f", "-e"])
        .arg(&binary)
        .arg(format!("{address:x}"))
        .output()
        .expect("run native addr2line");
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout).lines().next(),
        Some("local_function")
    );
    assert!(
        String::from_utf8_lossy(&native.stdout)
            .lines()
            .nth(1)
            // addr2line.c prints '?' for line == 0 with a fallback filename.
            .is_some_and(|line| line.ends_with(":?") || line.ends_with(":0")),
        "the queried assembly address must have no source line: {}",
        String::from_utf8_lossy(&native.stdout)
    );
    let frames = RustAddr2lineResolver::new()
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: binary,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve fallback frames");
    assert_eq!(frames, vec![vec!["local_function".to_string()]]);
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn bfd_fallback_without_file_symbols_preserves_debug_line_and_matches_native() {
    // GNU addr2line accepts BFD's function-only success as "??:?"; perf's
    // filename_split rejects only "??:0". Keep .debug_line so cmd__addr2line
    // can start, while removing only the optional STT_FILE associations.
    let (_root, binary, bytes) = compiled_bfd_zero_sized_alias_fixture();
    let object = object::File::parse(bytes.as_slice()).expect("fixture ELF");
    let debug_line = object
        .section_by_name(".debug_line")
        .expect("fixture debug line section")
        .data()
        .expect("fixture debug line data");
    assert!(!debug_line.is_empty());
    let mut file_symbols: Vec<_> = object
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::File)
        .map(|symbol| symbol.name().expect("file symbol name").to_string())
        .collect();
    assert!(!file_symbols.is_empty());
    file_symbols.sort_unstable();
    file_symbols.dedup();
    let mut command = Command::new("objcopy");
    for name in file_symbols {
        command.arg("--strip-symbol").arg(name);
    }
    let output = command
        .arg(&binary)
        .output()
        .expect("strip only fixture file symbols");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stripped = std::fs::read(&binary).expect("read fixture without file symbols");
    let object = object::File::parse(stripped.as_slice()).expect("stripped fixture ELF");
    assert!(
        object
            .symbols()
            .all(|symbol| symbol.kind() != SymbolKind::File)
    );
    assert_eq!(
        object
            .section_by_name(".debug_line")
            .expect("preserved debug line section")
            .data()
            .expect("preserved debug line data"),
        debug_line
    );
    let local = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("local_function"))
        .expect("preserved local function");
    let alias = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("global_alias"))
        .expect("preserved global alias");
    assert_eq!(local.size(), 16);
    assert_eq!(alias.size(), 0);
    assert_eq!(alias.address(), local.address());
    let address = local.address() + 24;
    let native = Command::new("addr2line")
        .args(["-f", "-i", "-e"])
        .arg(&binary)
        .arg(format!("{address:x}"))
        .output()
        .expect("run native addr2line without file symbols");
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let native_text = String::from_utf8_lossy(&native.stdout);
    assert_eq!(
        native_text.lines().collect::<Vec<_>>(),
        ["local_function", "??:?"]
    );
    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: binary,
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: address,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let resolver = RustAddr2lineResolver::new();
    let base = resolver
        .resolve_base_frame_batch_with_metadata(std::slice::from_ref(&request))
        .expect("resolve preserved perf base alias");
    assert_eq!(base[0].frames, ["global_alias+0x18"]);
    let frames = resolver
        .resolve_frame_batch(&[request])
        .expect("resolve function-only fallback frames");
    assert_eq!(frames, vec![vec!["local_function".to_string()]]);
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn bfd_fallback_accepts_nonzero_hidden_notype_symbols_rejected_by_perf() {
    // bfd/elf.c:_bfd_elf_maybe_function_sym rejects hidden local NOTYPE
    // only with zero st_size; perf symbol-elf.c filters all hidden labels.
    assert_bfd_fallback_assembly_matches_native(
        r#"
        ".globl outer_function\n"
        ".type outer_function,@function\n"
        "outer_function:\n"
        ".fill 8,1,0x90\n"
        ".hidden inner_label\n"
        ".type inner_label,@notype\n"
        "inner_label:\n"
        ".fill 24,1,0x90\n"
        ".size outer_function,32\n"
        ".size inner_label,8\n"
        "#,
        "outer_function",
        9,
        "inner_label",
    );
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn bfd_fallback_shortens_extents_in_canonical_order_before_alias_selection() {
    // bfd/dwarf2.c:_bfd_elf_find_function shortens its cached best extent
    // when a later canonical symbol starts beyond the queried address.
    assert_bfd_fallback_assembly_matches_native(
        r#"
        ".type local_function,@function\n"
        "local_function:\n"
        ".fill 8,1,0x90\n"
        ".type next_local,@function\n"
        "next_local:\n"
        ".fill 24,1,0x90\n"
        ".size local_function,32\n"
        ".size next_local,8\n"
        ".globl global_alias\n"
        ".type global_alias,@function\n"
        ".set global_alias,local_function\n"
        ".size global_alias,16\n"
        "#,
        "local_function",
        4,
        "local_function",
    );
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn bfd_fallback_prefers_ordinary_function_over_smaller_ifunc_alias() {
    // bfd/elfcode.h gives IFUNC BSF_GNU_INDIRECT_FUNCTION, not
    // BSF_FUNCTION. dwarf2.c:better_fit prefers FUNC before comparing size.
    assert_bfd_fallback_assembly_matches_native(
        r#"
        ".type local_function,@function\n"
        "local_function:\n"
        ".fill 32,1,0x90\n"
        ".size local_function,32\n"
        ".globl ifunc_alias\n"
        ".type ifunc_alias,@gnu_indirect_function\n"
        ".set ifunc_alias,local_function\n"
        ".size ifunc_alias,16\n"
        "#,
        "local_function",
        8,
        "local_function",
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn compiled_bfd_assembly_fixture(assembly: &str) -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let source = format!(
        "int with_source_line(void) {{ return 7; }}\n\
         __asm__(\".pushsection .text.alias_fixture,\\\"ax\\\",@progbits\\n\"\n\
         {assembly}\n\".popsection\\n\");"
    );
    compiled_c_fixture(&source)
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn bfd_fallback_preserves_native_function_cache_across_address_order() {
    // bfd/dwarf2.c:_bfd_elf_find_function reuses its previous winner while
    // the next address remains within the cached (possibly shortened) extent.
    let (_root, binary, bytes) = compiled_bfd_assembly_fixture(
        r#"
        ".type long_function_name,@function\n"
        "long_function_name:\n"
        ".fill 48,1,0x90\n"
        ".size long_function_name,48\n"
        ".type medium,@function\n"
        ".set medium,long_function_name\n"
        ".size medium,32\n"
        ".type short,@function\n"
        ".set short,long_function_name\n"
        ".size short,16\n"
        "#,
    );
    let object = object::File::parse(bytes.as_slice()).expect("fixture ELF");
    let base = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("long_function_name"))
        .expect("long function")
        .address();
    let addresses = [base + 4, base + 24, base + 8];
    let native = Command::new("addr2line")
        .args(["-f", "-i", "-e"])
        .arg(&binary)
        .args(addresses.map(|address| format!("{address:x}")))
        .output()
        .expect("run ordered native addr2line queries");
    assert!(native.status.success());
    let native_text = String::from_utf8_lossy(&native.stdout);
    let native_frames: Vec<_> = native_text.lines().step_by(2).map(str::to_string).collect();
    assert_eq!(native_frames.len(), 3, "{native_text}");
    assert_eq!(
        native_frames,
        ["short", "medium", "medium"],
        "native BFD must reuse its cached winner: {native_text}"
    );
    assert!(
        native_text
            .lines()
            .skip(1)
            .step_by(2)
            .all(|line| { line.ends_with(":?") || line.ends_with(":0") })
    );
    let requests = addresses.map(|address| SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: binary.clone(),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: address,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    });
    let frames = RustAddr2lineResolver::new()
        .resolve_frame_batch(&requests)
        .expect("resolve ordered fallback frames");
    assert_eq!(
        frames,
        native_frames
            .into_iter()
            .map(|name| vec![name])
            .collect::<Vec<_>>()
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn assert_bfd_fallback_assembly_matches_native(
    assembly: &str,
    query_symbol: &str,
    offset: u64,
    expected: &str,
) {
    let (_root, binary, bytes) = compiled_bfd_assembly_fixture(assembly);
    let object = object::File::parse(bytes.as_slice()).expect("fixture ELF");
    let address = object
        .symbols()
        .find(|symbol| symbol.name() == Ok(query_symbol))
        .expect("query symbol")
        .address()
        + offset;
    let native = Command::new("addr2line")
        .args(["-f", "-i", "-e"])
        .arg(&binary)
        .arg(format!("{address:x}"))
        .output()
        .expect("run native addr2line");
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let native_text = String::from_utf8_lossy(&native.stdout);
    assert_eq!(native_text.lines().next(), Some(expected), "{native_text}");
    assert!(
        native_text
            .lines()
            .nth(1)
            .is_some_and(|line| line.ends_with(":?") || line.ends_with(":0")),
        "assembly address must have no source line: {native_text}"
    );
    let frames = RustAddr2lineResolver::new()
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: binary,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve fallback frames");
    assert_eq!(frames, vec![vec![expected.to_string()]]);
}

#[test]
fn rust_addr2line_resolver_keeps_elf_outer_name_for_cargo_read_to_end() {
    // Linux v7.2.9 tools/perf/util/libdw.c:85-96 retains the ELF outer
    // symbol, rather than falsely marking the shorter DIE name as inlined.
    let cargo = PathBuf::from(
        "/nix/store/wy162cxyays1rj57blywar8y5ybvjx8l-cargo-1.95.0-x86_64-unknown-linux-gnu/bin/cargo",
    );
    if !cargo.exists() {
        return;
    }

    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: cargo.clone(),
        // PERF_RECORD_MMAP2 maps cargo at 0x6231444cf000 with file offset
        // 0x6fc000. perf's `map__dso_map_ip` first forms 0x1763636, then
        // `map__rip_2objdump` adds the user-DSO text offset 0x1000.
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0x0176_4636,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };

    let expected = vec!["std::io::default_read_to_end::<std::fs::File>".to_string()];
    assert_eq!(
        perf_dwarf_frame_names_from_object(&cargo, request.relative_address),
        Some(expected.clone())
    );

    let resolver = RustAddr2lineResolver::new();
    assert_eq!(
        resolver
            .resolve_frame_batch(&[request])
            .expect("resolve cargo frame"),
        vec![vec![
            "std::io::default_read_to_end::<std::fs::File>+0xe6".to_string()
        ]]
    );
}

#[test]
fn rust_addr2line_resolver_uses_addr2line_realfunc_record_for_rust_object_alias_like_perf() {
    // Reference fixture:
    //   perf script --inline -i /tmp/backend768.perf.data
    // prints `<&str as core::fmt::Display>::fmt+0x3 (inlined)` for this
    // cargo address. The symtab also has a global alias at the same address,
    // `<cargo::util::interning::InternedString as core::fmt::Display>::fmt`,
    // but perf's addr2line path can still use the first function record as a
    // fake inline symbol when it differs from the base symbol.
    //
    // Relevant perf source:
    // - tools/perf/util/addr2line.c cmd__addr2line() appends the first
    //   addr2line record when unwinding inline frames.
    // - tools/perf/util/srcline.c new_inline_sym() creates a fake inlined
    //   symbol when that record's function name differs from the base symbol.
    // - tools/perf/util/symbol.c choose_best_symbol() explains why this is not
    //   just the normal duplicate-symtab tie breaker.
    let cargo = PathBuf::from(
        "/nix/store/wy162cxyays1rj57blywar8y5ybvjx8l-cargo-1.95.0-x86_64-unknown-linux-gnu/bin/cargo",
    );
    if !cargo.exists() {
        return;
    }

    let resolver = RustAddr2lineResolver::new();
    assert_eq!(
        resolver
            .resolve_frame_batch(&[SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path: cargo,
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0x0106_d883,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }])
            .expect("resolve cargo alias frame"),
        vec![vec!["<&str as core::fmt::Display>::fmt".to_string()]]
    );
}

#[test]
fn rust_addr2line_resolver_uses_perf_dwarf_names_for_inline_frames() {
    let Some((profiling_binary, object_bytes)) = profiling_binary_fixture() else {
        return;
    };
    let Some(address) = find_profiling_address(&object_bytes, |frames| frames.len() > 1) else {
        return;
    };

    let resolver = RustAddr2lineResolver::new();
    let frames = resolver
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: profiling_binary.clone(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve frames");

    let expected = perf_dwarf_frame_names_from_object(&profiling_binary, address)
        .map(perf_inline_frame_order)
        .expect("perf dwarf frames");

    assert_eq!(frames, vec![expected]);
}

#[test]
fn addr2line_resolver_uses_perf_dwarf_names_for_inline_frames() {
    let Some((profiling_binary, object_bytes)) = profiling_binary_fixture() else {
        return;
    };
    let Some(address) = find_profiling_address(&object_bytes, |frames| frames.len() > 1) else {
        return;
    };
    let runner =
        Addr2lineRunner::new(b"gimli::read::line::LineProgramHeader<R,Offset>::parse\n??:0\n");
    let resolver = Addr2lineResolver::new(&runner);

    let frames = resolver
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: profiling_binary.clone(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve frames");

    let expected = perf_dwarf_frame_names_from_object(&profiling_binary, address)
        .map(perf_inline_frame_order)
        .expect("perf dwarf frames");

    assert_eq!(frames, vec![expected]);
}

#[test]
fn addr2line_inline_resolver_requires_a_perf_base_symbol() {
    // perf util/machine.c:append_inlines rejects a NULL ms->sym before
    // calling libdw__addr2line or the binutils addr2line subprocess.
    let object = tempfile::NamedTempFile::new().unwrap();
    let runner = Addr2lineRunner::new(b"invented_without_a_base_symbol\n??:0\n");
    let resolver = Addr2lineResolver::new(&runner);
    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: object.path().to_path_buf(),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0x1000,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let results = resolver
        .resolve_frame_batch_with_metadata(&[request])
        .unwrap();
    assert!(results[0].frames.is_empty());
    assert!(!results[0].has_base_symbol);
    assert!(runner.commands().is_empty());
}

#[test]
fn rust_addr2line_resolver_uses_object_symbol_for_non_inline_frames_like_perf_script() {
    let Some((profiling_binary, object_bytes)) = profiling_binary_fixture() else {
        return;
    };
    let Some((address, _)) =
        rust_resolved_frames_for_text_symbols(&profiling_binary, &object_bytes)
            .and_then(|frames| frames.into_iter().find(|(_, frames)| frames.len() == 1))
    else {
        return;
    };

    let resolver = RustAddr2lineResolver::new();
    let frames = resolver
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: profiling_binary.clone(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve frames");

    let expected = external_addr2line_frames_root_to_leaf(&profiling_binary, address)
        .and_then(|frames| frames.into_iter().next())
        .expect("external addr2line frame");
    // tools/perf/util/symbol_fprintf.c symbol__fprintf_symname_offs()
    // appends +0xoffset for perf-script symbol output, including +0x0.
    assert_eq!(frames, vec![vec![format!("{expected}+0x0")]]);
}

#[test]
fn rust_addr2line_resolver_synthesizes_x86_64_plt_symbols_like_perf_script() {
    let libc =
        PathBuf::from("/nix/store/57iz36553175g3178pvxjij8z5rcsd4n-glibc-2.42-61/lib/libc.so.6");
    if !libc.exists() {
        return;
    }

    let resolver = RustAddr2lineResolver::new();
    let frames = resolver
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: libc,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x287a4,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve frames");

    assert_eq!(frames, vec![vec!["strcmp@plt+0x4".to_string()]]);
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn non_pie_plt_symbols_use_virtual_addresses_after_mapping_translation() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("fixture.c");
    let binary = root.path().join("fixture");
    std::fs::write(
        &source,
        "#include <stdio.h>\nint main(void) { puts(\"hello\"); return 0; }\n",
    )
    .unwrap();
    let output = Command::new("cc")
        .args(["-fno-pie", "-no-pie", "-g"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(&binary).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let plt = object.section_by_name(".plt").unwrap();
    assert_ne!(plt.address(), plt.file_range().unwrap().0);
    let address = plt.file_range().unwrap().0 + 16;
    let resolver =
        pyroclast::symbols::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new());
    let mut request = test_symbol_request(0, 0);
    request.path = binary;
    request.relative_address = address;
    let frames = resolver
        .resolve_base_frame_batch_with_metadata(&[request])
        .unwrap();
    assert_eq!(frames[0].frames, vec!["puts@plt+0x0"]);
}

#[test]
fn rust_addr2line_resolver_replaces_base_symbol_when_perf_inline_name_differs() {
    let Some((profiling_binary, object_bytes)) = profiling_binary_fixture() else {
        return;
    };
    let Some((address, expected_symbol)) = rust_resolved_symbols_for_text_symbols(
        &profiling_binary,
        &object_bytes,
    )
    .and_then(|symbols| {
        let loader = addr2line::Loader::new(&profiling_binary).ok()?;
        symbols.into_iter().find_map(|(address, symbol)| {
            let expected_symbol = symbol?;
            let raw_base_symbol = loader.find_symbol(address).map(|name| {
                perf_dwarf_function_name(&addr2line::demangle_auto(Cow::Borrowed(name), None))
            })?;
            (raw_base_symbol != expected_symbol).then_some((address, expected_symbol))
        })
    }) else {
        return;
    };

    let resolver = RustAddr2lineResolver::new();
    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: profiling_binary,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve symbols");

    assert_eq!(symbols, vec![Some(expected_symbol.clone())]);
}

fn profiling_binary_fixture() -> Option<(PathBuf, Vec<u8>)> {
    let profiling_binary = PathBuf::from("target/profiling/pyroclast");
    let bytes = match std::fs::read(&profiling_binary) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!(
                "optional profiling-binary coverage skipped ({}): {error}; run cargo build --profile profiling to enable it",
                profiling_binary.display()
            );
            return None;
        }
    };
    Some((profiling_binary, bytes))
}

#[cfg(target_os = "linux")]
fn compiled_c_fixture(source: &str) -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let root = tempfile::tempdir().expect("fixture directory");
    let source_path = root.path().join("fixture.c");
    let binary = root.path().join("fixture.so");
    std::fs::write(&source_path, source).expect("write fixture source");
    let output = Command::new("cc")
        .args(["-g", "-O0", "-fPIC", "-shared"])
        .arg(&source_path)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("compile C fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(&binary).expect("read fixture object");
    (root, binary, bytes)
}

fn find_profiling_address(
    object_bytes: &[u8],
    predicate: impl Fn(&[String]) -> bool,
) -> Option<u64> {
    profiling_dwarf_candidate_addresses(object_bytes)
        .into_iter()
        .find(|address| {
            perf_dwarf_frame_names_from_object_bytes(object_bytes, *address)
                .is_some_and(|frames| predicate(&frames))
        })
}

fn text_symbol_addresses(object_bytes: &[u8]) -> Vec<u64> {
    text_symbol_addresses_matching_name(object_bytes, |_| true)
}

fn generic_dwarf_name_candidate_addresses(object_bytes: &[u8]) -> Vec<u64> {
    profiling_dwarf_candidate_addresses(object_bytes)
}

fn profiling_dwarf_candidate_addresses(object_bytes: &[u8]) -> Vec<u64> {
    text_symbol_addresses_matching_name(object_bytes, |name| {
        (name.contains("BTreeMap") && name.contains("insert"))
            || (name.contains("IntoIter") && name.contains("dying_next"))
            || name.contains("insert_recursing")
    })
}

fn text_symbol_addresses_matching_name(
    object_bytes: &[u8],
    mut name_matches: impl FnMut(&str) -> bool,
) -> Vec<u64> {
    let object = object::File::parse(object_bytes).expect("object file");
    let mut addresses = object
        .symbols()
        .filter(|symbol| {
            symbol.address() != 0
                && symbol.kind() == SymbolKind::Text
                && symbol.name().is_ok_and(&mut name_matches)
        })
        .flat_map(|symbol| {
            let mut candidates = vec![symbol.address()];
            if symbol.size() > 1 {
                candidates.push(symbol.address().saturating_add(1));
            }
            if symbol.size() > 2 {
                candidates.push(symbol.address().saturating_add(symbol.size() / 2));
            }
            candidates
        })
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

fn rust_resolved_frames_for_text_symbols(
    profiling_binary: &Path,
    object_bytes: &[u8],
) -> Option<Vec<(u64, Vec<String>)>> {
    let addresses = text_symbol_addresses(object_bytes)
        .into_iter()
        .take(512)
        .collect::<Vec<_>>();
    let requests = symbol_requests(profiling_binary, &addresses);
    let resolved = RustAddr2lineResolver::new()
        .resolve_frame_batch(&requests)
        .ok()?;
    Some(addresses.into_iter().zip(resolved).collect())
}

fn rust_resolved_symbols_for_text_symbols(
    profiling_binary: &Path,
    object_bytes: &[u8],
) -> Option<Vec<(u64, Option<String>)>> {
    let addresses = text_symbol_addresses(object_bytes)
        .into_iter()
        .take(512)
        .collect::<Vec<_>>();
    let requests = symbol_requests(profiling_binary, &addresses);
    let resolved = RustAddr2lineResolver::new().resolve_batch(&requests).ok()?;
    Some(addresses.into_iter().zip(resolved).collect())
}

fn symbol_requests(profiling_binary: &Path, addresses: &[u64]) -> Vec<SymbolRequest> {
    addresses
        .iter()
        .map(|address| SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: profiling_binary.to_path_buf(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: *address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        })
        .collect()
}

fn external_addr2line_frames_leaf_to_root(path: &Path, address: u64) -> Option<Vec<String>> {
    let output = Command::new("addr2line")
        .args([
            "-f",
            "-i",
            "-C",
            "-e",
            path.to_str()?,
            &format!("0x{address:x}"),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let frames = stdout
        .lines()
        .step_by(2)
        .filter(|name| *name != "??")
        .map(perf_dwarf_function_name)
        .collect::<Vec<_>>();
    (!frames.is_empty()).then_some(frames)
}

fn external_addr2line_frames_root_to_leaf(path: &Path, address: u64) -> Option<Vec<String>> {
    external_addr2line_frames_leaf_to_root(path, address).map(perf_inline_frame_order)
}

/// Runs `addr2line -f -i -e` exactly like perf's external-addr2line backend
/// (tools/perf/util/addr2line.c `addr2line_subprocess_init` passes `-a -i -f`
/// and never `-C`), then demangles each mangled function-name line with the
/// Rust alternate demangle the way perf's `new_inline_sym` -> `dso__demangle_sym`
/// does. `addr2line::demangle_auto` is byte-identical to perf's alternate Rust
/// demangle for both legacy `_ZN` and v0 `_R` symbols.
fn external_addr2line_linkage_frames_root_to_leaf(
    path: &Path,
    address: u64,
) -> Option<Vec<String>> {
    let output = Command::new("addr2line")
        .args(["-f", "-i", "-e", path.to_str()?, &format!("0x{address:x}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let frames = stdout
        .lines()
        .step_by(2)
        .filter(|name| *name != "??")
        .map(|name| addr2line::demangle_auto(Cow::Borrowed(name), None).into_owned())
        .collect::<Vec<_>>();
    (!frames.is_empty()).then(|| perf_inline_frame_order(frames))
}

#[test]
fn perf_inline_frame_order_matches_perf_script_root_to_leaf() {
    assert_eq!(
        perf_inline_frame_order(vec!["value_name".to_string(), "augment_args".to_string()]),
        vec!["augment_args".to_string(), "value_name".to_string()]
    );
}

#[test]
fn addr2line_resolver_treats_failed_batches_without_object_aliases_as_unresolved() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("app");
    std::fs::write(&path, elf_with_dynamic_text_symbol(b"app", 0x1000, 46))
        .expect("write regular object");
    let runner = Addr2lineRunner::failed();
    let resolver = Addr2lineResolver::new(&runner);

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path: path.clone(),
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0x10,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path,
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0x20,
                kernel_mapping_range: None,
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
fn kallsyms_space_suffixes_do_not_create_module_views() {
    let original = "\
ffffffff81001280 T asm_exc_page_fault
ffffffffc0e17dae t zfs_read [zfs]
ffffffffc0e17e10 t zfs_write [zfs]
";
    assert!(Kallsyms::parse_modules(original).is_err());
    assert_live_space_suffix_name(original, 0xffff_ffff_c0e1_7dae, "zfs_read [zfs]");
    for module in ["[zfs]", "[igb]", "[nf_tables]"] {
        assert!(Kallsyms::parse_modules_for_path(original, module).is_err());
    }
}

fn assert_live_space_suffix_name(text: &str, address: u64, expected: &str) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("kallsyms");
    std::fs::write(&path, text).unwrap();
    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_map_candidates([])
        .with_system_kallsyms_from_path(&path);
    let actual = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: address,
            kernel_module_address: None,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .unwrap();
    assert_eq!(actual, [Some(format!("{expected}+0x0"))]);
}

#[test]
fn kallsyms_parse_modules_only_keeps_module_symbols_canonical_tab() {
    let symbols = Kallsyms::parse_modules(
        "\
ffffffff81001280 T asm_exc_page_fault
ffffffffc0e17dae t zfs_read\t[zfs]
ffffffffc0e17e10 t zfs_write\t[zfs]
",
    )
    .expect("module kallsyms");

    assert_eq!(
        symbols.resolve(0xffff_ffff_c0e1_7dae).as_deref(),
        Some("zfs_read")
    );
    assert_eq!(symbols.resolve(0xffff_ffff_8100_1280), None);
}
#[test]
fn kallsyms_space_suffixes_do_not_select_requested_module() {
    let original = "\
ffffffff81001280 T asm_exc_page_fault
ffffffffc0e17dae t zfs_read [zfs]
ffffffffc0e17e10 t zfs_write [zfs]
ffffffffc1e17dae t igb_clean_rx_irq [igb]
";
    assert!(Kallsyms::parse_modules(original).is_err());
    assert_live_space_suffix_name(original, 0xffff_ffff_c1e1_7dae, "igb_clean_rx_irq [igb]");
    for module in ["[zfs]", "[igb]", "[nf_tables]"] {
        assert!(Kallsyms::parse_modules_for_path(original, module).is_err());
    }
}

#[test]
fn kallsyms_parse_modules_for_path_only_keeps_requested_module_canonical_tab() {
    let symbols = Kallsyms::parse_modules_for_path(
        "\
ffffffff81001280 T asm_exc_page_fault
ffffffffc0e17dae t zfs_read\t[zfs]
ffffffffc0e17e10 t zfs_write\t[zfs]
ffffffffc1e17dae t igb_clean_rx_irq\t[igb]
",
        "[zfs]",
    )
    .expect("module kallsyms");

    assert_eq!(
        symbols.resolve(0xffff_ffff_c0e1_7dae).as_deref(),
        Some("zfs_read")
    );
    assert_ne!(
        symbols.resolve(0xffff_ffff_c1e1_7dae).as_deref(),
        Some("igb_clean_rx_irq")
    );
    assert_eq!(symbols.resolve(0xffff_ffff_8100_1280), None);
}
#[test]
fn kallsyms_space_suffix_data_rows_remain_core_only() {
    let original = "\
ffffffffc0cd6220 d empty_dataset_kstats [zfs]
ffffffffc0ce2e00 d __this_module [zfs]
ffffffffc0e53510 t __pfx_zfs_ZSTD_getCParamsFromCCtxParams [zfs]
ffffffffc0e53520 t zfs_ZSTD_getCParamsFromCCtxParams [zfs]
";
    assert!(Kallsyms::parse_modules(original).is_err());
    assert_live_space_suffix_name(
        original,
        0xffff_ffff_c0cd_6220,
        "empty_dataset_kstats [zfs]",
    );
    for module in ["[zfs]", "[igb]", "[nf_tables]"] {
        assert!(Kallsyms::parse_modules_for_path(original, module).is_err());
    }
}

#[test]
fn kallsyms_module_resolution_keeps_data_symbols_inside_perf_module_map_canonical_tab() {
    let symbols = Kallsyms::parse_modules_for_path(
        "\
ffffffffc0cd6220 d empty_dataset_kstats\t[zfs]
ffffffffc0ce2e00 d __this_module\t[zfs]
ffffffffc0e53510 t __pfx_zfs_ZSTD_getCParamsFromCCtxParams\t[zfs]
ffffffffc0e53520 t zfs_ZSTD_getCParamsFromCCtxParams\t[zfs]
",
        "[zfs]",
    )
    .expect("module kallsyms");

    assert_eq!(
        symbols
            .resolve_module_with_offset(0xffff_ffff_c0e5_35fe)
            .as_deref(),
        Some("zfs_ZSTD_getCParamsFromCCtxParams+0xde")
    );
    // perf keeps D/B kallsyms in symbol_type__filter() and split module
    // symbols in maps__split_kallsyms(); map__find_symbol() then bounds the
    // lookup to the map that contained the sampled IP.
    assert_eq!(
        symbols
            .resolve_module_with_offset_in_range(
                0xffff_ffff_c0cd_7303,
                Some((0xffff_ffff_c0cd_6000, 0xffff_ffff_c0cd_8000)),
            )
            .as_deref(),
        Some("empty_dataset_kstats+0x10e3")
    );
    assert_eq!(
        symbols.resolve_module_with_offset_in_range(
            0xffff_ffff_c0ce_9720,
            Some((0xffff_ffff_c0ce_9000, 0xffff_ffff_c0ce_a000)),
        ),
        None
    );
}
#[test]
fn kallsyms_space_suffix_rows_do_not_bound_module_symbols() {
    let original = "\
ffffffffc0ce2e00 d __this_module [zfs]
ffffffffc0ce31a0 t nft_do_chain [nf_tables]
ffffffffc0e53520 t zfs_ZSTD_getCParamsFromCCtxParams [zfs]
";
    assert!(Kallsyms::parse_modules(original).is_err());
    assert_live_space_suffix_name(original, 0xffff_ffff_c0ce_2e00, "__this_module [zfs]");
    for module in ["[zfs]", "[igb]", "[nf_tables]"] {
        assert!(Kallsyms::parse_modules_for_path(original, module).is_err());
    }
}

#[test]
fn kallsyms_module_resolution_caps_symbol_end_at_next_global_module_symbol_like_perf_script_canonical_tab()
 {
    let symbols = Kallsyms::parse_modules_for_path(
        "\
ffffffffc0ce2e00 d __this_module\t[zfs]
ffffffffc0ce31a0 t nft_do_chain\t[nf_tables]
ffffffffc0e53520 t zfs_ZSTD_getCParamsFromCCtxParams\t[zfs]
",
        "[zfs]",
    )
    .expect("module kallsyms");

    // perf fixes zero-sized kallsyms extents across the full symbol tree before
    // maps__split_kallsyms() moves module symbols into per-module DSOs.
    assert_eq!(
        symbols.resolve_module_with_offset(0xffff_ffff_c0ce_9720),
        None
    );
}
#[test]
fn kallsyms_space_suffix_far_row_does_not_create_module() {
    let original = "\
ffffffffc11dc2b0 T nft_chain_route_init [nf_tables]
";
    assert!(Kallsyms::parse_modules(original).is_err());
    assert_live_space_suffix_name(
        original,
        0xffff_ffff_c11d_c2b0,
        "nft_chain_route_init [nf_tables]",
    );
    for module in ["[zfs]", "[igb]", "[nf_tables]"] {
        assert!(Kallsyms::parse_modules_for_path(original, module).is_err());
    }
}

#[test]
fn kallsyms_module_resolution_rejects_far_gaps_like_perf_script_symbols_find_canonical_tab() {
    let symbols = Kallsyms::parse_modules_for_path(
        "\
ffffffffc11dc2b0 T nft_chain_route_init\t[nf_tables]
",
        "[nf_tables]",
    )
    .expect("module kallsyms");

    assert_eq!(
        symbols
            .resolve_module_with_offset(0xffff_ffff_c11d_c2b0)
            .as_deref(),
        Some("nft_chain_route_init+0x0")
    );
    assert_eq!(
        symbols.resolve_module_with_offset(0xffff_ffff_c179_61e4),
        None
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
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("app");
    std::fs::write(&path, elf_with_dynamic_text_symbol(b"app", 0x1000, 46))
        .expect("write regular object");
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
                addr2line_address: None,
                kernel_module_address: None,
                path: PathBuf::from("[kernel.kallsyms]"),
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0xffff_ffff_8800_008f,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path,
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0x10,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
        ])
        .expect("symbols");

    // perf-script prints kernel frames as `name+0x<off>`
    // (tools/perf/util/symbol_fprintf.c __symbol__fprintf_symname_offs); the
    // folded path strips the offset like every other frame.
    assert_eq!(
        symbols,
        vec![
            Some("asm_exc_page_fault+0xf".to_string()),
            Some("app::main".to_string())
        ]
    );
    assert_eq!(runner.commands().len(), 1);
    // The valid ELF fixture translates file-relative 0x10 to VA 0x1010.
    assert_eq!(
        runner.commands()[0].stdin.as_deref(),
        Some(&b"0x1010\n"[..])
    );
}

fn load_module_test_core(resolver: &impl SymbolResolver) {
    // perf util/symbol.c:dso__load:1866 marks even failed DSOs loaded;
    // maps__split_kallsyms:918-920 excludes those modules from the core split.
    // Core-first may populate module DSOs; no later per-address resurrection.
    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8469_97a0,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("core symbols");
    assert_eq!(symbols, vec![Some("__pi_memcpy+0x0".to_string())]);
}

#[test]
fn perf_symbol_resolver_module_first_does_not_mix_selected_kallsyms_with_live_modules() {
    check_selected_core_only_kallsyms_with_live_modules(false);
}

#[test]
fn perf_symbol_resolver_core_first_does_not_mix_selected_kallsyms_with_live_modules() {
    check_selected_core_only_kallsyms_with_live_modules(true);
}

fn check_selected_core_only_kallsyms_with_live_modules(core_first: bool) {
    // perf v7.2.9 symbol.c:2199-2216 keeps a selected file's misses;
    // the native-first selected-source fixture in perfdata_fold covers this.
    let cached = Kallsyms::parse(
        "ffffffff846997a0 T __pi_memcpy\nffffffff8501cd2c R xen_elfnote_phys32_entry\n",
    )
    .expect("cached kallsyms");
    let space_rows = "\
ffffffff8501cd2c R xen_elfnote_phys32_entry
ffffffffc0e66100 t zpl_iter_read [zfs]
ffffffffc0e66200 t zpl_iter_read_next [zfs]
";
    assert!(Kallsyms::parse_modules(space_rows).is_err());
    let live = Kallsyms::parse_modules(
        "ffffffff8501cd2c R xen_elfnote_phys32_entry\nffffffffc0e66100 t zpl_iter_read\t[zfs]\nffffffffc0e66200 t zpl_iter_read_next\t[zfs]\n",
    )
    .expect("live module kallsyms");
    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_kallsyms(cached)
        .with_live_kallsyms(live);

    if core_first {
        load_module_test_core(&resolver);
    }

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[zfs]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_c0e6_61e9,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![None]);
    if !core_first {
        load_module_test_core(&resolver);
    }
    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[zfs]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_c0e6_61ea,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("another module address after core loading");
    assert_eq!(symbols, vec![None]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_module_gap_uses_one_backend_lookup_and_preserves_user_mode() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("module.ko");
    std::fs::write(&path, elf_with_static_text_symbol(b"entry", 0x1000, 64)).unwrap();
    let fixture_resolver = RustAddr2lineResolver::new();
    assert_eq!(
        fixture_resolver
            .resolve_batch(&[SymbolRequest {
                path: path.clone(),
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0x1010,
                addr2line_address: None,
                kernel_module_address: None,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }])
            .unwrap(),
        [Some("entry".into())]
    );
    let object = ObservedRustResolver {
        inner: RustAddr2lineResolver::new(),
        calls: RefCell::new(Vec::new()),
    };
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(&object)
        .with_kallsyms(Kallsyms::parse("ffffffff846997a0 T __pi_memcpy\n").unwrap());
    load_module_test_core(&resolver);
    let request = SymbolRequest {
        path,
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0x10,
        addr2line_address: None,
        kernel_module_address: Some(0xffff_ffff_c100_0010),
        kernel_mapping_range: Some((0xffff_ffff_c100_0000, 0xffff_ffff_c100_1000)),
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let requests = [
        request.clone(),
        SymbolRequest {
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x80,
            kernel_module_address: Some(0xffff_ffff_c100_0080),
            ..request.clone()
        },
        SymbolRequest {
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x1010,
            kernel_module_address: None,
            kernel_mapping_range: None,
            ..request
        },
    ];
    let symbols = resolver.resolve_batch(&requests).unwrap();
    assert_eq!(symbols, [Some("entry".into()), None, Some("entry".into())]);
    assert_eq!(*object.calls.borrow(), [("base", 2), ("bare", 1)]);
    object.calls.borrow_mut().clear();
    let base = resolver
        .resolve_base_frame_batch_with_metadata(&requests)
        .unwrap();
    assert_eq!(
        base.into_iter()
            .map(|frames| frames.frames.into_iter().next())
            .collect::<Vec<_>>(),
        [Some("entry+0x10".into()), None, Some("entry+0x10".into())]
    );
    assert_eq!(*object.calls.borrow(), [("base", 3)]);
}

#[test]
fn selected_kallsyms_core_misses_do_not_fall_through_to_other_sources() {
    let root = tempfile::tempdir().unwrap();
    let elf = root.path().join("vmlinux");
    std::fs::write(
        &elf,
        elf_with_dynamic_text_symbol(b"alternative_core", 0xffff_ffff_8100_0000, 64),
    )
    .unwrap();
    let selected = || {
        pyroclast::symbols::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new())
            .with_kallsyms(Kallsyms::parse("ffffffff82000000 T selected_core\n").unwrap())
    };
    let alternative = "ffffffff81000000 T alternative_core\n";
    let request = SymbolRequest {
        path: "[kernel.kallsyms]".into(),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0xffff_ffff_8100_0010,
        addr2line_address: None,
        kernel_module_address: None,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let mut actual = Vec::new();
    let mut source_states = Vec::new();
    for (source, resolver) in [
        (
            "live",
            selected().with_live_kallsyms(Kallsyms::parse(alternative).unwrap()),
        ),
        (
            "system-map",
            selected().with_system_map_kallsyms(Kallsyms::parse(alternative).unwrap()),
        ),
        ("elf", selected().with_kernel_elf(elf)),
    ] {
        let symbols = resolver
            .resolve_batch(std::slice::from_ref(&request))
            .unwrap();
        let base = resolver
            .resolve_base_frame_batch_with_metadata(std::slice::from_ref(&request))
            .unwrap();
        let inline = resolver
            .resolve_frame_batch_with_metadata(std::slice::from_ref(&request))
            .unwrap();
        source_states.extend(base.iter().chain(&inline).map(|frames| frames.source_state));
        actual.push((
            source,
            symbols,
            base.into_iter()
                .map(|frames| frames.frames)
                .collect::<Vec<_>>(),
            inline
                .into_iter()
                .map(|frames| frames.frames)
                .collect::<Vec<_>>(),
        ));
    }
    assert_eq!(
        actual,
        ["live", "system-map", "elf"].map(|source| (
            source,
            vec![None],
            vec![Vec::<String>::new()],
            vec![Vec::<String>::new()]
        ))
    );
    assert!(
        source_states
            .iter()
            .all(|state| *state == pyroclast::symbols::SymbolSourceState::AddressDependent)
    );
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
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]_text"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_1280,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: Some(pyroclast::symbols::KernelRelocation {
                reference_symbol: "_text".to_string(),
                recorded_reference_address: 0xffff_ffff_8800_0000,
            }),
        }])
        .expect("symbols");

    // The relocated address lands on the symbol start, so perf prints +0x0.
    assert_eq!(symbols, vec![Some("asm_exc_page_fault+0x0".to_string())]);
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
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_008f,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("asm_exc_page_fault+0xf".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_loads_kernel_build_id_cache_from_delivered_maps() {
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
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_008f,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("asm_exc_page_fault+0xf".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_loads_kernel_metadata_only_with_delivered_kernel_maps() {
    // tools/perf/util/symbol.c:dso__load loads a DSO on demand, not when
    // constructing a session that may contain only user-space samples.
    let root = tempfile::tempdir().unwrap();
    let perfdata = root.path().join("perf.data");
    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_perfdata_file_kernel_cache(&perfdata, root.path());

    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).unwrap();
    let cached = root
        .path()
        .join("[kernel.kallsyms]")
        .join("16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949")
        .join("kallsyms");
    std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
    std::fs::write(cached, "ffffffff88000080 t asm_exc_page_fault\n").unwrap();
    resolver.initialize_kernel_maps(&kernel_build_id_maps());
    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_008f,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .unwrap();
    assert_eq!(symbols, vec![Some("asm_exc_page_fault+0xf".to_string())]);
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
fn perf_build_id_elf_path_uses_vdso_cache_layout_like_perf_script() {
    assert_eq!(
        perf_build_id_elf_path_for_dso(
            &PathBuf::from("/home/mjc/.debug"),
            Path::new("[vdso]"),
            "b622c2813bd4cfe887f1c9e8e63d60ed782841d4",
        ),
        PathBuf::from("/home/mjc/.debug/[vdso]/b622c2813bd4cfe887f1c9e8e63d60ed782841d4/vdso")
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
        // nixos_system_map_path canonicalizes the kernel image, so resolve the
        // expectation through tempdir symlinks (macOS /var -> /private/var).
        Some(std::fs::canonicalize(&system_map).expect("canonicalize system map"))
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
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_008f,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    // perf-script kernel frames carry +0x<off> (symbol_fprintf.c); folded
    // output strips it.
    assert_eq!(symbols, vec![Some("cached_kernel_symbol+0xf".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_does_not_use_system_map_for_recorded_kernel_build_id_without_cache() {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");
    let system_map = home.path().join("System.map");
    std::fs::write(
        &system_map,
        "ffffffff88000080 T bogus_current_kernel_symbol\n",
    )
    .expect("system map");

    let runner = Addr2lineRunner::new(b"");
    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        pyroclast::symbols::Addr2lineResolver::new(&runner),
        &perfdata,
        home.path(),
        [system_map],
        &home.path().join("kallsyms"),
    );
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_008f,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![None]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_module_first_build_id_without_cache_stays_unknown() {
    check_live_module_build_id_without_cache(false, false);
}

#[test]
fn kallsyms_space_suffix_build_id_rows_do_not_create_live_modules() {
    check_live_module_build_id_without_cache(true, false);
}

#[test]
fn perf_symbol_resolver_core_first_uses_live_module_kallsyms_without_build_id_cache_canonical_tab()
{
    check_live_module_build_id_without_cache(true, true);
}

#[test]
fn perf_symbol_resolver_module_first_build_id_without_cache_stays_unknown_canonical_tab() {
    check_live_module_build_id_without_cache(false, true);
}

fn check_live_module_build_id_without_cache(core_first: bool, canonical_tab: bool) {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");
    let live_kallsyms = home.path().join("kallsyms");
    let space_rows = "ffffffff846997a0 T __pi_memcpy\nffffffffc0ed5900 t arc_read [zfs]\n";
    let rows = if canonical_tab {
        "ffffffff846997a0 T __pi_memcpy\nffffffffc0ed5900 t arc_read\t[zfs]\n"
    } else {
        assert_live_space_suffix_name(space_rows, 0xffff_ffff_c0ed_5900, "arc_read [zfs]");
        space_rows
    };
    std::fs::write(&live_kallsyms, rows).expect("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        pyroclast::symbols::Addr2lineResolver::new(&runner),
        &perfdata,
        home.path(),
        [],
        &live_kallsyms,
    );
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    if core_first {
        load_module_test_core(&resolver);
    }

    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: PathBuf::from("[zfs]"),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0xffff_ffff_c0ed_5ffa,
        kernel_mapping_range: Some((0xffff_ffff_c0e0_0000, 0xffff_ffff_c10f_0000)),
        build_id: Some("25c900692553622cb73db68330349ea739893267".to_string()),
        file_identity: None,
        kernel_relocation: None,
    };
    let symbols = resolver
        .resolve_batch(std::slice::from_ref(&request))
        .expect("symbols");

    // A recorded module build-ID does not prevent core-first kallsyms use,
    // but it does not let a failed module-first load repopulate its DSO.
    assert_eq!(
        symbols,
        vec![(core_first && canonical_tab).then(|| "arc_read+0x6fa".to_string())]
    );
    if !core_first {
        load_module_test_core(&resolver);
        assert_eq!(
            resolver.resolve_batch(&[request]).expect("retry"),
            vec![None]
        );
    }
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_uses_relocated_live_kallsyms_despite_recorded_build_id_like_perf_script() {
    check_relocated_live_kallsyms_reference('T');
}

#[test]
fn perf_symbol_resolver_accepts_absolute_relocation_alias_without_inserting_it_as_a_symbol() {
    // perf event.c:find_func_symbol_cb accepts uppercase A as a relocation
    // alias, but symbol.c:symbol_type__filter excludes it from the DSO tree.
    check_relocated_live_kallsyms_reference('A');
}

fn check_relocated_live_kallsyms_reference(reference_type: char) {
    let root = tempfile::tempdir().expect("root");
    let perfdata = root.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");
    let live_kallsyms = root.path().join("kallsyms");
    std::fs::write(
        &live_kallsyms,
        format!(
            "\
ffffffff91200000 {reference_type} _text
ffffffff91200000 T _stext
ffffffff914e8fa0 t mp_map_pin_to_irq
"
        ),
    )
    .expect("kallsyms");
    let live_notes = root.path().join("notes");
    std::fs::write(&live_notes, b"not the recorded build id").expect("notes");

    let runner = Addr2lineRunner::new(b"");
    let resolver = perf_symbol_resolver_for_perfdata_file_with_object(
        pyroclast::symbols::Addr2lineResolver::new(&runner),
        &perfdata,
        root.path(),
    )
    .with_system_kallsyms_from_path(&live_kallsyms)
    .with_live_kernel_notes_path(live_notes);
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_90ee_91f1,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: Some(pyroclast::symbols::KernelRelocation {
                reference_symbol: "_text".to_string(),
                recorded_reference_address: 0xffff_ffff_90c0_0000,
            }),
        }])
        .expect("symbols");

    // perf's dso__find_kallsyms() falls back to kallsyms, and
    // kallsyms__delta() relocates that table using the recorded reference
    // symbol before symbol_fprintf.c prints `name+0x<off>`.
    assert_eq!(symbols, vec![Some("mp_map_pin_to_irq+0x251".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_uses_perfdata_kallsyms_when_cached_kernel_elf_is_invalid() {
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
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_008f,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    // perf-script kernel frames carry +0x<off> (symbol_fprintf.c).
    assert_eq!(symbols, vec![Some("__pi_memcpy+0xf".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_rejects_invalid_kernel_build_id_elf_when_kallsyms_is_missing() {
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
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_008f,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![None]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_rejects_kernel_elf_without_a_build_id_note_when_request_omits_id() {
    check_kernel_build_id_elf_note(false);
}

#[test]
fn perf_symbol_resolver_uses_matching_kernel_build_id_elf_when_kallsyms_is_missing() {
    check_kernel_build_id_elf_note(true);
}

fn check_kernel_build_id_elf_note(matching_note: bool) {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");
    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let kernel_elf =
        pyroclast::symbols::perf_build_id_elf_path(&perf_debug_dir(home.path()), build_id);
    std::fs::create_dir_all(kernel_elf.parent().expect("kernel elf parent")).expect("cache dir");
    let image = elf_with_static_text_symbol(b"asm_exc_page_fault", 0xffff_ffff_8800_0080, 46);
    let bytes = if matching_note {
        let mut builder = build::elf::Builder::read(image.as_slice()).unwrap();
        let note_image = elf_with_recorded_build_id(build_id);
        let note_object = object::File::parse(note_image.as_slice()).unwrap();
        let note = note_object.section_by_name(".note.gnu.build-id").unwrap();
        let section = builder.sections.add();
        section.name = b".note.gnu.build-id"[..].into();
        section.sh_type = elf::SHT_NOTE;
        section.sh_addralign = 4;
        section.data =
            build::elf::SectionData::Data(object::ObjectSection::data(&note).unwrap().into());
        builder.set_section_sizes();
        let mut bytes = Vec::new();
        builder.write(&mut bytes).unwrap();
        bytes
    } else {
        image
    };
    std::fs::write(&kernel_elf, bytes).expect("regular kernel elf");
    // Native-first missing/matching note coverage lives in perfdata_fold;
    // symbol-elf.c:1228-1247 validates the DSO ID, not just a request's ID.
    let resolver =
        pyroclast::symbols::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new())
            .with_perfdata_file_kernel_cache(&perfdata, &perf_debug_dir(home.path()));
    resolver.initialize_kernel_maps(&kernel_build_id_maps());
    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_008f,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");
    assert_eq!(
        symbols,
        vec![matching_note.then(|| "asm_exc_page_fault".to_string())]
    );
}

#[test]
fn perf_symbol_resolver_uses_system_kallsyms_when_kernel_elf_is_invalid() {
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
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8469_97ac,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    // perf-script kernel frames carry +0x<off> (symbol_fprintf.c).
    assert_eq!(symbols, vec![Some("__pi_memcpy+0xc".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_prefers_live_kallsyms_over_system_map_like_perf_for_host_kernel() {
    let root = tempfile::tempdir().expect("root");
    let live_kallsyms = root.path().join("kallsyms");
    std::fs::write(&live_kallsyms, "ffffffff846997a0 T __pi_memcpy\n").expect("kallsyms");
    let system_map = root.path().join("System.map");
    std::fs::write(
        &system_map,
        "\
ffffffff846997a0 T __pi_memcpy
ffffffff846997a0 T memcpy
",
    )
    .expect("system map");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_kallsyms_from_path(&live_kallsyms)
        .with_system_map_candidates([system_map]);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8469_97ac,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    // tools/perf/util/symbol.c dso__find_kallsyms() fast-paths
    // /proc/kallsyms for the host kernel before falling back to cached
    // kallsyms/System.map sources. perf-script prints +0x<off>.
    assert_eq!(symbols, vec![Some("__pi_memcpy+0xc".to_string())]);
}

#[test]
fn perf_symbol_resolver_module_first_does_not_load_live_kallsyms() {
    check_lazy_live_module_kallsyms(false, false);
}

#[test]
fn kallsyms_space_suffix_lazy_rows_do_not_create_live_modules() {
    check_lazy_live_module_kallsyms(true, false);
}

#[test]
fn perf_symbol_resolver_core_first_loads_live_module_kallsyms_lazily_canonical_tab() {
    check_lazy_live_module_kallsyms(true, true);
}

#[test]
fn perf_symbol_resolver_module_first_does_not_load_live_kallsyms_canonical_tab() {
    check_lazy_live_module_kallsyms(false, true);
}

fn check_lazy_live_module_kallsyms(core_first: bool, canonical_tab: bool) {
    let root = tempfile::tempdir().expect("root");
    let live_kallsyms = root.path().join("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_kallsyms_from_path(&live_kallsyms);

    let space_rows = "\
ffffffff846997a0 T __pi_memcpy
ffffffffc0e17dae t zfs_read [zfs]
";
    let rows = if canonical_tab {
        "ffffffff846997a0 T __pi_memcpy\nffffffffc0e17dae t zfs_read\t[zfs]\n"
    } else {
        assert_live_space_suffix_name(space_rows, 0xffff_ffff_c0e1_7dae, "zfs_read [zfs]");
        space_rows
    };
    std::fs::write(&live_kallsyms, rows).expect("kallsyms");
    std::fs::write(
        root.path().join("modules"),
        "zfs 4096 0 - Live 0xffffffffc0e17000\n",
    )
    .expect("modules");

    if core_first {
        load_module_test_core(&resolver);
    }
    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[zfs]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_c0e1_7dae,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    // perf-script kernel/module frames carry +0x<off> (symbol_fprintf.c).
    assert_eq!(
        symbols,
        vec![(core_first && canonical_tab).then(|| "zfs_read+0x0".to_string())]
    );
    if !core_first {
        load_module_test_core(&resolver);
        let symbols = resolver
            .resolve_batch(&[SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path: PathBuf::from("[zfs]"),
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0xffff_ffff_c0e1_7dae,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }])
            .expect("retry after core loading");
        assert_eq!(symbols, vec![None]);
    }
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_module_first_stays_unknown_regardless_of_recorded_bounds() {
    check_live_module_recorded_bounds(false, false);
}

#[test]
fn kallsyms_space_suffix_recorded_bounds_do_not_create_live_modules() {
    check_live_module_recorded_bounds(true, false);
}

#[test]
fn perf_symbol_resolver_core_first_rejects_live_module_symbol_start_before_recorded_map_canonical_tab()
 {
    check_live_module_recorded_bounds(true, true);
}

#[test]
fn perf_symbol_resolver_module_first_stays_unknown_regardless_of_recorded_bounds_canonical_tab() {
    check_live_module_recorded_bounds(false, true);
}

#[test]
fn kallsyms_space_suffix_owner_names_do_not_create_live_modules() {
    check_live_module_owners(false);
}

#[test]
fn perf_symbol_resolver_core_first_rejects_live_symbols_from_other_modules_canonical_tab() {
    check_live_module_owners(true);
}

fn check_live_module_owners(canonical_tab: bool) {
    // Linux v7.2.9 symbol.c:maps__split_kallsyms assigns symbols by module
    // name; maps.c:maps__find_symbol looks up only the address's selected map.
    let root = tempfile::tempdir().expect("root");
    let live_kallsyms = root.path().join("kallsyms");
    let space_rows = "ffffffff846997a0 T __pi_memcpy\n\
         ffffffffc0002000 T alpha_entry [alpha]\n\
         ffffffffc0003000 T beta_entry [beta]\n";
    let rows = if canonical_tab {
        "ffffffff846997a0 T __pi_memcpy\nffffffffc0002000 T alpha_entry\t[alpha]\nffffffffc0003000 T beta_entry\t[beta]\n"
    } else {
        assert_live_space_suffix_name(space_rows, 0xffff_ffff_c000_2000, "alpha_entry [alpha]");
        assert_live_space_suffix_name(space_rows, 0xffff_ffff_c000_3000, "beta_entry [beta]");
        space_rows
    };
    std::fs::write(&live_kallsyms, rows).expect("kallsyms");
    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_kallsyms_from_path(&live_kallsyms);
    load_module_test_core(&resolver);

    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: PathBuf::from("[alpha]"),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0xffff_ffff_c000_2008,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let actual = resolver
        .resolve_batch(&[
            request.clone(),
            SymbolRequest {
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0xffff_ffff_c000_3008,
                ..request.clone()
            },
            SymbolRequest {
                path: PathBuf::from("[missing]"),
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0xffff_ffff_c000_3008,
                ..request
            },
        ])
        .expect("module lookups");
    assert_eq!(
        actual,
        vec![canonical_tab.then(|| "alpha_entry+0x8".into()), None, None]
    );
    assert!(runner.commands().is_empty());
}

#[test]
fn shared_kernel_resolution_rejects_addresses_beyond_file_backed_core_map() {
    // perf v7.2.9 maps.c:731-738 selects a containing map before symbols;
    // symbols__fixup_end bounds the final kallsyms symbol to its page.
    let root = tempfile::tempdir().expect("root");
    let kallsyms = root.path().join("kallsyms");
    std::fs::write(
        &kallsyms,
        "ffffffff88000000 T _stext\nffffffff88001000 T core_tail\n",
    )
    .expect("file-backed kallsyms");
    let resolver =
        pyroclast::symbols::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new())
            .with_system_kallsyms_from_path(&kallsyms);
    let address = 0xffff_ffff_8800_7000;
    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: "[kernel.kallsyms]".into(),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: address,
        kernel_mapping_range: Some((0xffff_ffff_8800_0000, 0xffff_ffff_8800_2000)),
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let requests = [
        SymbolRequest {
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8800_1010,
            ..request.clone()
        },
        request,
    ];
    for ordinary in [
        resolver
            .resolve_base_frame_batch_with_metadata(&requests)
            .expect("bounded base resolution"),
        resolver
            .resolve_frame_batch_with_metadata(&requests)
            .expect("bounded inline resolution"),
    ] {
        assert_eq!(ordinary[0].frames, ["core_tail+0x10"]);
        assert!(ordinary[1].frames.is_empty(), "{ordinary:?}");
        assert_eq!(
            ordinary[1].kernel_dso,
            pyroclast::symbols::SymbolDsoName::Unmapped
        );
    }
}

#[test]
fn module_projection_metadata_is_scoped_to_its_resolver_owner() {
    use pyroclast::symbols::SymbolLookup;

    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("module.ko");
    std::fs::write(&path, elf_with_static_text_symbol(b"entry", 0x1000, 64))
        .expect("write module ELF");
    let request = SymbolRequest {
        path: path.clone(),
        relative_address: 0x1010,
        symbol_lookup: SymbolLookup::VirtualAddress,
        addr2line_address: None,
        kernel_module_address: Some(0xffff_ffff_c100_0010),
        kernel_mapping_range: Some((0xffff_ffff_c100_0000, 0xffff_ffff_c100_1000)),
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };

    let resolver_a = RustAddr2lineResolver::new();
    let metadata_a = resolver_a
        .selected_object_module_metadata(&path, &request)
        .expect("resolver A module metadata");
    let projection_a = metadata_a
        .lookup_projection
        .expect("resolver A projection ID");
    let (section, file_offset) = metadata_a.text_section.expect("module text layout");
    let foreign_request = SymbolRequest {
        symbol_lookup: SymbolLookup::KernelModuleSection {
            projection: projection_a,
            section,
            offset: file_offset + 0x10,
        },
        ..request.clone()
    };

    let resolver_b = RustAddr2lineResolver::new();
    let foreign = resolver_b
        .resolve_base_frame_batch_with_metadata(std::slice::from_ref(&foreign_request))
        .expect("foreign projection lookup is nonfatal");
    assert!(foreign[0].frames.is_empty());
    assert!(!foreign[0].has_base_symbol);

    let metadata_b = resolver_b
        .selected_object_module_metadata(&path, &request)
        .expect("resolver B module metadata");
    let projection_b = metadata_b
        .lookup_projection
        .expect("resolver B projection ID");
    assert_ne!(projection_a, projection_b);
    let (section, file_offset) = metadata_b.text_section.expect("module text layout");
    let owned_request = SymbolRequest {
        symbol_lookup: SymbolLookup::KernelModuleSection {
            projection: projection_b,
            section,
            offset: file_offset + 0x10,
        },
        ..request
    };
    let owned = resolver_b
        .resolve_base_frame_batch_with_metadata(&[owned_request])
        .expect("resolver B own projection lookup");
    assert_eq!(owned[0].frames, ["entry+0x10"]);
    assert!(owned[0].has_base_symbol);
}

fn check_live_module_recorded_bounds(core_first: bool, canonical_tab: bool) {
    let root = tempfile::tempdir().expect("root");
    let live_kallsyms = root.path().join("kallsyms");
    let space_rows = "\
ffffffff846997a0 T __pi_memcpy
ffffffffc11dc2b0 T nft_chain_route_init [nf_tables]
ffffffffc1800000 T later_nf_tables_symbol [nf_tables]
";
    let rows = if canonical_tab {
        "ffffffff846997a0 T __pi_memcpy\nffffffffc11dc2b0 T nft_chain_route_init\t[nf_tables]\nffffffffc1800000 T later_nf_tables_symbol\t[nf_tables]\n"
    } else {
        assert_live_space_suffix_name(
            space_rows,
            0xffff_ffff_c11d_c2b0,
            "nft_chain_route_init [nf_tables]",
        );
        assert_live_space_suffix_name(
            space_rows,
            0xffff_ffff_c180_0000,
            "later_nf_tables_symbol [nf_tables]",
        );
        space_rows
    };
    std::fs::write(&live_kallsyms, rows).expect("kallsyms");
    std::fs::write(
        root.path().join("modules"),
        "nf_tables 401408 201 nft_compat,nft_chain_nat, Live 0xffffffffc11dc000\n",
    )
    .expect("modules");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_kallsyms_from_path(&live_kallsyms);

    if core_first {
        load_module_test_core(&resolver);
    }

    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: PathBuf::from("[nf_tables]"),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0xffff_ffff_c11d_c2c0,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    // perf util/maps.c:maps__find and symbol.c:maps__split_kallsyms keep
    // module symbols in their map. The address is in this recorded map, but
    // the live symbol starts before it; neither module bounds nor a symbol
    // gap may independently reject the core-first positive control.
    let symbols = resolver
        .resolve_batch(&[
            request.clone(),
            SymbolRequest {
                kernel_mapping_range: Some((0xffff_ffff_c11d_c2b8, 0xffff_ffff_c11d_c300)),
                ..request.clone()
            },
        ])
        .expect("symbols");

    assert_eq!(
        symbols,
        vec![
            (core_first && canonical_tab).then(|| "nft_chain_route_init+0x10".to_string()),
            None
        ]
    );
    if !core_first {
        load_module_test_core(&resolver);
        assert_eq!(
            resolver.resolve_batch(&[request]).expect("retry"),
            vec![None]
        );
    }
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_module_first_stays_unknown_across_core_snapshot_loading() {
    check_live_module_kallsyms_snapshot(false, false);
}

#[test]
fn kallsyms_space_suffix_snapshot_rows_do_not_create_live_modules() {
    check_live_module_kallsyms_snapshot(true, false);
}

#[test]
fn perf_symbol_resolver_core_first_uses_a_single_live_kallsyms_snapshot_for_modules_canonical_tab()
{
    check_live_module_kallsyms_snapshot(true, true);
}

#[test]
fn perf_symbol_resolver_module_first_stays_unknown_across_core_snapshot_loading_canonical_tab() {
    check_live_module_kallsyms_snapshot(false, true);
}

fn check_live_module_kallsyms_snapshot(core_first: bool, canonical_tab: bool) {
    let root = tempfile::tempdir().expect("root");
    let live_kallsyms = root.path().join("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_kallsyms_from_path(&live_kallsyms);

    let space_rows = "\
ffffffff846997a0 T __pi_memcpy
ffffffffc0e17dae t zfs_read [zfs]
ffffffffc1e17dae t igb_clean_rx_irq [igb]
";
    let rows = if canonical_tab {
        "ffffffff846997a0 T __pi_memcpy\nffffffffc0e17dae t zfs_read\t[zfs]\nffffffffc1e17dae t igb_clean_rx_irq\t[igb]\n"
    } else {
        assert_live_space_suffix_name(space_rows, 0xffff_ffff_c0e1_7dae, "zfs_read [zfs]");
        assert_live_space_suffix_name(space_rows, 0xffff_ffff_c1e1_7dae, "igb_clean_rx_irq [igb]");
        space_rows
    };
    std::fs::write(&live_kallsyms, rows).expect("kallsyms");
    std::fs::write(
        root.path().join("modules"),
        "\
zfs 4096 0 - Live 0xffffffffc0e17000
igb 4096 0 - Live 0xffffffffc1e17000
",
    )
    .expect("modules");

    if core_first {
        load_module_test_core(&resolver);
    }
    let zfs = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: PathBuf::from("[zfs]"),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0xffff_ffff_c0e1_7dae,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let symbols = resolver
        .resolve_batch(std::slice::from_ref(&zfs))
        .expect("symbols");
    // perf-script kernel/module frames carry +0x<off> (symbol_fprintf.c).
    assert_eq!(
        symbols,
        vec![(core_first && canonical_tab).then(|| "zfs_read+0x0".to_string())]
    );
    if !core_first {
        // Capture the core snapshot only after zfs has completed its failed
        // load. igb is still unattempted and can receive rows from this split.
        load_module_test_core(&resolver);
    }

    let replacement_space_rows = "\
ffffffff846997a0 T __pi_memcpy
ffffffffc2e17dae t unrelated_module_symbol [mlx5]
";
    let replacement_rows = if canonical_tab {
        "ffffffff846997a0 T __pi_memcpy\nffffffffc2e17dae t unrelated_module_symbol\t[mlx5]\n"
    } else {
        replacement_space_rows
    };
    std::fs::write(&live_kallsyms, replacement_rows).expect("kallsyms");

    let igb = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: PathBuf::from("[igb]"),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0xffff_ffff_c1e1_7dae,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let symbols = resolver.resolve_batch(&[zfs, igb]).expect("symbols");

    assert_eq!(
        symbols,
        vec![
            (core_first && canonical_tab).then(|| "zfs_read+0x0".to_string()),
            canonical_tab.then(|| "igb_clean_rx_irq+0x0".to_string())
        ]
    );
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_base_module_first_build_id_miss_stays_unknown() {
    check_base_module_build_id_miss(false, false);
}

#[test]
fn kallsyms_space_suffix_base_build_id_miss_does_not_create_live_modules() {
    check_base_module_build_id_miss(true, false);
}

#[test]
fn perf_symbol_resolver_base_core_first_uses_module_kallsyms_after_build_id_miss_canonical_tab() {
    check_base_module_build_id_miss(true, true);
}

#[test]
fn perf_symbol_resolver_base_module_first_build_id_miss_stays_unknown_canonical_tab() {
    check_base_module_build_id_miss(false, true);
}

fn check_base_module_build_id_miss(core_first: bool, canonical_tab: bool) {
    let root = tempfile::tempdir().expect("root");
    let debug_dir = perf_debug_dir(root.path());
    let live_kallsyms = root.path().join("kallsyms");
    let build_id = "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949";
    let cached_module = perf_build_id_elf_path_for_dso(&debug_dir, Path::new("[zfs]"), build_id);
    std::fs::create_dir_all(cached_module.parent().expect("parent")).expect("cache dir");
    std::fs::write(&cached_module, b"not an elf").expect("cached module marker");
    let space_rows = "\
ffffffff846997a0 T __pi_memcpy
ffffffffc0e38940 t nvs_xdr_nvp_op [zfs]
";
    let rows = if canonical_tab {
        "ffffffff846997a0 T __pi_memcpy\nffffffffc0e38940 t nvs_xdr_nvp_op\t[zfs]\n"
    } else {
        assert_live_space_suffix_name(space_rows, 0xffff_ffff_c0e3_8940, "nvs_xdr_nvp_op [zfs]");
        space_rows
    };
    std::fs::write(&live_kallsyms, rows).expect("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_debug_dir(debug_dir)
        .with_system_kallsyms_from_path(&live_kallsyms);

    if core_first {
        load_module_test_core(&resolver);
    }

    let request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
        path: PathBuf::from("[zfs]"),
        symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
        relative_address: 0xffff_ffff_c0e3_8b71,
        kernel_mapping_range: None,
        build_id: Some(build_id.to_string()),
        file_identity: None,
        kernel_relocation: None,
    };
    let frames = resolver
        .resolve_base_frame_batch_with_metadata(std::slice::from_ref(&request))
        .expect("frames");

    assert_eq!(
        frames,
        vec![pyroclast::symbols::ResolvedSymbolFrames {
            frames: (core_first && canonical_tab)
                .then(|| "nvs_xdr_nvp_op+0x231".to_string())
                .into_iter()
                .collect(),
            source_state: pyroclast::symbols::SymbolSourceState::AddressDependent,
            kernel_dso: pyroclast::symbols::SymbolDsoName::Mapping,
            has_base_symbol: core_first && canonical_tab,
            has_inline_frames: false,
            has_non_inline_base_frame: core_first && canonical_tab,
            base_offset: None,
        }]
    );
    if !core_first {
        load_module_test_core(&resolver);
        let retry = resolver
            .resolve_base_frame_batch_with_metadata(&[request])
            .expect("retry");
        assert_eq!(retry, frames);
    }
}

#[test]
fn perf_symbol_resolver_loads_system_map_lazily_and_keeps_last_equal_address_alias() {
    let root = tempfile::tempdir().expect("root");
    let system_map = root.path().join("System.map");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_map_candidates([system_map.clone()]);

    std::fs::write(
        &system_map,
        "\
ffffffff846997a0 T __pi_memcpy
ffffffff846997a0 T memcpy
",
    )
    .expect("system map");

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8469_97ac,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    // tools/perf/util/symbol.c symbols__fixup_end(..., true) gives the last
    // equal-address kallsyms alias the extent; symbols__fixup_duplicate() then
    // keeps that nonzero-length alias. perf-script prints +0x<off>.
    assert_eq!(symbols, vec![Some("memcpy+0xc".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
#[cfg(target_os = "linux")]
fn perf_symbol_resolver_note_only_module_elf_stays_unknown_without_bare_gnu_lookup() {
    let home = tempfile::tempdir().expect("home");
    let build_id = "d6ed2003b20b59c61cdc649124d920215521fc00";
    let module_elf =
        pyroclast::symbols::perf_build_id_elf_path(&perf_debug_dir(home.path()), build_id);
    std::fs::create_dir_all(module_elf.parent().unwrap()).unwrap();
    let bytes = elf_with_recorded_build_id(build_id);
    let object = object::File::parse(bytes.as_slice()).unwrap();
    assert_eq!(object.symbols().count(), 0);
    assert_eq!(object.dynamic_symbols().count(), 0);
    std::fs::write(&module_elf, bytes).unwrap();
    let native = Command::new("addr2line")
        .args(["-f", "-C", "-e"])
        .arg(&module_elf)
        .arg("0x30")
        .output()
        .expect("native GNU addr2line");
    assert!(native.status.success(), "{native:?}");
    assert_eq!(native.stdout, b"??\n??:0\n");

    // Keep the former canned response to detect an unsupported bare lookup.
    // perf v7.2.9 map.c:383-388 requires a symbol in the selected DSO.
    let runner = Addr2lineRunner::new(b"igb_clean_rx_irq\n??:0\n");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_debug_dir(perf_debug_dir(home.path()));
    let actual = resolver
        .resolve_batch(&[SymbolRequest {
            path: "[igb]".into(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x30,
            addr2line_address: None,
            kernel_module_address: None,
            kernel_mapping_range: None,
            build_id: Some(build_id.into()),
            file_identity: None,
            kernel_relocation: None,
        }])
        .unwrap();
    assert_eq!(actual, [None]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_rejects_dynsym_only_module_build_id_elf() {
    check_module_build_id_elf(false);
}

#[test]
fn perf_symbol_resolver_uses_symtab_module_build_id_elf() {
    check_module_build_id_elf(true);
}

fn check_module_build_id_elf(has_symtab: bool) {
    let home = tempfile::tempdir().expect("home");
    let build_id = "d6ed2003b20b59c61cdc649124d920215521fc00";
    let module_elf =
        pyroclast::symbols::perf_build_id_elf_path(&perf_debug_dir(home.path()), build_id);
    std::fs::create_dir_all(module_elf.parent().expect("module elf parent")).expect("cache dir");
    let image = if has_symtab {
        elf_with_static_text_symbol(b"igb_clean_rx_irq", 0, 64)
    } else {
        elf_with_dynamic_text_symbol(b"igb_clean_rx_irq", 0, 64)
    };
    let mut builder = build::elf::Builder::read(image.as_slice()).unwrap();
    let note_image = elf_with_recorded_build_id(build_id);
    let note_object = object::File::parse(note_image.as_slice()).unwrap();
    let note_section = note_object.section_by_name(".note.gnu.build-id").unwrap();
    let section = builder.sections.add();
    section.name = b".note.gnu.build-id"[..].into();
    section.sh_type = elf::SHT_NOTE;
    section.sh_addralign = 4;
    section.data =
        build::elf::SectionData::Data(object::ObjectSection::data(&note_section).unwrap().into());
    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    std::fs::write(&module_elf, bytes).expect("module elf");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_debug_dir(perf_debug_dir(home.path()));

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[igb]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x30,
            kernel_mapping_range: None,
            build_id: Some(build_id.to_string()),
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![has_symtab.then(|| "igb_clean_rx_irq".into())]);
    // Kernel DSOs require SYMTAB even if DYNSYM contains an eligible symbol.
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_uses_vdso_build_id_cache_layout_like_perf_script() {
    let home = tempfile::tempdir().expect("home");
    let build_id = "b622c2813bd4cfe887f1c9e8e63d60ed782841d4";
    let vdso_elf =
        perf_build_id_elf_path_for_dso(&perf_debug_dir(home.path()), Path::new("[vdso]"), build_id);
    std::fs::create_dir_all(vdso_elf.parent().expect("vdso elf parent")).expect("cache dir");
    std::fs::write(&vdso_elf, elf_with_recorded_build_id(build_id)).expect("vdso elf");

    let runner = Addr2lineRunner::new(b"__vdso_clock_gettime\n??:0\n");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_debug_dir(perf_debug_dir(home.path()));

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[vdso]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x970,
            kernel_mapping_range: None,
            build_id: Some(build_id.to_string()),
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("__vdso_clock_gettime".to_string())]);
    assert_eq!(runner.commands()[0].stdin.as_deref(), Some(&b"0x970\n"[..]));
    assert_eq!(
        runner.commands()[0].args,
        vec![
            "-f".to_string(),
            "-C".to_string(),
            "-e".to_string(),
            vdso_elf.display().to_string(),
        ]
    );
}

#[test]
#[cfg(target_os = "linux")]
fn perf_symbol_resolver_uses_live_vdso_copy_without_build_id_like_perf_script() {
    let object_resolver = FixedRecordingResolver::new(Some("__vdso_getrandom".to_string()));
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(&object_resolver);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[vdso]"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x129a,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("__vdso_getrandom".to_string())]);
    let calls = object_resolver.batch_calls();
    assert_eq!(calls.len(), 1);
    let rewritten_request = &calls[0][0];
    assert_ne!(rewritten_request.path, Path::new("[vdso]"));
    assert!(
        rewritten_request.path.exists(),
        "live vDSO copy should stay alive while resolver is alive"
    );
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn perf_symbol_resolver_does_not_use_native_vdso_for_compat_requests() {
    // perf util/map.c:map__new only special-cases vdso.h:is_vdso_map's
    // "[vdso]" map name. The compat DSO names are not native map names.
    let object_resolver = FixedRecordingResolver::new(None);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(&object_resolver);
    let requests: Vec<_> = ["[vdso]", "[vdso32]", "[vdsox32]"]
        .into_iter()
        .map(|path| SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from(path),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x100,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        })
        .collect();
    resolver.resolve_batch(&requests).expect("symbols");
    let calls = object_resolver.batch_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].len(), 3);
    let native_elf = std::fs::read(&calls[0][0].path).expect("native vDSO positive control");
    let native_image = object::File::parse(native_elf.as_slice()).expect("native vDSO ELF");
    assert!(object::Object::is_64(&native_image));
    for (request, delegated) in requests[1..].iter().zip(&calls[0][1..]) {
        let path = &request.path;
        let delegated = &delegated.path;
        assert_eq!(
            delegated,
            Path::new(path),
            "compat DSO used native vDSO image"
        );
    }
}

#[test]
fn perf_symbol_resolver_accepts_pluggable_object_resolver() {
    let object_resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(object_resolver);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("app::main".to_string())]);
    assert_eq!(
        resolver.object_resolver().batch_calls(),
        vec![vec![SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn perf_symbol_resolver_translates_live_object_file_offsets_to_virtual_addresses() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_path_buf();
    let bytes = elf_with_dynamic_text_symbol(b"pie_function", 0x5000, 32);
    std::fs::write(&path, &bytes).unwrap();
    let object = object::File::parse(bytes.as_slice()).expect("fixture ELF");
    assert_eq!(object.kind(), object::ObjectKind::Dynamic);
    let (file_offset, virtual_address) = object
        .segments()
        .find_map(|segment| {
            let (file_offset, file_size) = segment.file_range();
            let virtual_address = segment.address();
            (file_size > 8 && virtual_address != file_offset)
                .then_some((file_offset + 8, virtual_address + 8))
        })
        .expect("fixture ELF has a biased load segment");
    let object_resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: path.clone(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: virtual_address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(object_resolver);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: path.clone(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: file_offset,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("app::main".to_string())]);
    assert_eq!(
        resolver.object_resolver().batch_calls(),
        vec![vec![SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path,
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: virtual_address,
            kernel_mapping_range: None,
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
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        vec!["app::outer".to_string(), "app::inner".to_string()],
    )]);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(object_resolver);

    let frames = resolver
        .resolve_frame_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("/bin/app"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
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
fn perf_symbol_resolver_uses_live_user_object_despite_recorded_identity_mismatch_like_perf() {
    let object_path = tempfile::NamedTempFile::new().expect("object file");
    let object_resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: object_path.path().to_path_buf(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(object_resolver);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: object_path.path().to_path_buf(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
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

    assert_eq!(symbols, vec![Some("app::main".to_string())]);
    assert_eq!(
        resolver.object_resolver().batch_calls(),
        vec![vec![SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: object_path.path().to_path_buf(),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0x10,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }]]
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
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
            path: PathBuf::from("[kernel.kallsyms]_text"),
            symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
            relative_address: 0xffff_ffff_8100_1280,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    // perf-script kernel frames carry +0x<off> (symbol_fprintf.c); the
    // relocated address lands on the symbol start.
    assert_eq!(symbols, vec![Some("asm_exc_page_fault+0x0".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_keeps_live_kallsyms_for_modules_when_system_map_exists() {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");
    let system_map = home.path().join("System.map");
    std::fs::write(&system_map, "ffffffff81001280 T asm_exc_page_fault\n").expect("system map");
    let kallsyms = home.path().join("kallsyms");
    std::fs::write(&kallsyms, "ffffffffc0e17dae t zfs_read\t[zfs]\n").expect("kallsyms");
    std::fs::write(
        home.path().join("modules"),
        "zfs 4096 0 - Live 0xffffffffc0e17000\n",
    )
    .expect("modules");

    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        RecordingResolver::default(),
        &perfdata,
        home.path(),
        [system_map],
        &kallsyms,
    );
    resolver.initialize_kernel_maps(&kernel_build_id_maps());

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path: PathBuf::from("[kernel.kallsyms]_text"),
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0xffff_ffff_8100_1280,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
                path: PathBuf::from("[zfs]"),
                symbol_lookup: pyroclast::symbols::SymbolLookup::VirtualAddress,
                relative_address: 0xffff_ffff_c0e1_7dae,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
        ])
        .expect("symbols");

    // perf-script kernel/module frames carry +0x<off> (symbol_fprintf.c).
    assert_eq!(
        symbols,
        vec![
            Some("asm_exc_page_fault+0x0".to_string()),
            Some("zfs_read+0x0".to_string())
        ]
    );
}

#[derive(Default)]
struct RecordingResolver {
    symbols: BTreeMap<SymbolRequest, String>,
    frames: BTreeMap<SymbolRequest, Vec<String>>,
    calls: RefCell<Vec<Vec<SymbolRequest>>>,
}

struct ObservedRustResolver {
    inner: RustAddr2lineResolver,
    calls: RefCell<Vec<(&'static str, usize)>>,
}

impl SymbolResolver for &ObservedRustResolver {
    fn selected_object_module_metadata(
        &self,
        path: &Path,
        module: &SymbolRequest,
    ) -> Option<std::sync::Arc<pyroclast::symbols::KernelModuleObjectMetadata>> {
        self.inner.selected_object_module_metadata(path, module)
    }

    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.calls.borrow_mut().push(("bare", requests.len()));
        self.inner.resolve_batch(requests)
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<pyroclast::symbols::ResolvedSymbolFrames>, String> {
        self.calls.borrow_mut().push(("base", requests.len()));
        self.inner.resolve_base_frame_batch_with_metadata(requests)
    }
}

fn perfdata_with_kernel_build_id() -> Vec<u8> {
    let build_id = [
        0x16, 0xed, 0x3d, 0x53, 0x17, 0xad, 0x21, 0x9c, 0x89, 0xd0, 0xe3, 0xc5, 0xea, 0x0e, 0xa2,
        0xca, 0xa3, 0xcd, 0x49, 0x49,
    ];
    let mut payload = build_id_event_payload(u32::MAX, &build_id, "[kernel.kallsyms]");
    // header.c:__event_process_build_id rejects misc=0; host kernel is 1.
    payload[4..6].copy_from_slice(&1_u16.to_le_bytes());
    perfdata_with_build_id_feature(&payload)
}

fn kernel_build_id_maps() -> pyroclast::perfdata::mappings::MmapTable {
    // Supply the delivered map/DSO header context, rather than asking a symbol
    // resolver to replay future records from the file (perf map.c:map__load).
    let mut record = Vec::new();
    record.extend(1_u32.to_le_bytes());
    record.extend(1_u16.to_le_bytes());
    record.extend(72_u16.to_le_bytes());
    record.extend(u32::MAX.to_le_bytes());
    record.extend(0_u32.to_le_bytes());
    record.extend(0xffff_ffff_8800_0000_u64.to_le_bytes());
    record.extend(0x1000_u64.to_le_bytes());
    record.extend(0_u64.to_le_bytes());
    record.extend(b"[kernel.kallsyms]\0");
    record.resize(72, 0);
    let mut bytes = perfdata_with_kernel_build_id();
    bytes.splice(128..128, record);
    put_u64(&mut bytes, 48, 72);
    put_u64(&mut bytes, 200, 232);
    pyroclast::perfdata::fold::summarize_perfdata(&bytes)
        .expect("delivered kernel map")
        .mmap_table
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
    // HEADER_BUILD_ID feature bit (2) in the adds_features bitmap at byte
    // offset 72 (struct perf_file_header, tools/perf/util/header.h).
    put_u64(&mut bytes, 72, 1 << 2);
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

#[cfg(target_os = "linux")]
struct FixedRecordingResolver {
    symbol: Option<String>,
    calls: RefCell<Vec<Vec<SymbolRequest>>>,
}

#[cfg(target_os = "linux")]
impl FixedRecordingResolver {
    fn new(symbol: Option<String>) -> Self {
        Self {
            symbol,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn batch_calls(&self) -> Vec<Vec<SymbolRequest>> {
        self.calls.borrow().clone()
    }
}

#[cfg(target_os = "linux")]
impl SymbolResolver for &FixedRecordingResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.calls.borrow_mut().push(requests.to_vec());
        Ok(vec![self.symbol.clone(); requests.len()])
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

fn elf_with_recorded_build_id(build_id: &str) -> Vec<u8> {
    assert!(build_id.len().is_multiple_of(2));
    let id = build_id
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let mut note = Vec::new();
    note.extend_from_slice(&4_u32.to_le_bytes());
    note.extend_from_slice(&u32::try_from(id.len()).unwrap().to_le_bytes());
    note.extend_from_slice(&elf::NT_GNU_BUILD_ID.to_le_bytes());
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(&id);
    note.resize(note.len().next_multiple_of(4), 0);

    let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
    builder.header.e_type = elf::ET_DYN;
    builder.header.e_machine = elf::EM_X86_64;
    let section = builder.sections.add();
    section.name = b".shstrtab"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.data = build::elf::SectionData::SectionString;
    let section = builder.sections.add();
    section.name = b".note.gnu.build-id"[..].into();
    section.sh_type = elf::SHT_NOTE;
    section.sh_addralign = 4;
    section.data = build::elf::SectionData::Data(note.into());
    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    assert_eq!(object.build_id().unwrap(), Some(id.as_slice()));
    bytes
}

fn elf_with_static_text_symbol(name: &'static [u8], address: u64, size: usize) -> Vec<u8> {
    let mut object = object::write::Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::X86_64,
        object::Endianness::Little,
    );
    let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
    object.section_mut(text).set_data(vec![0xcc; size], 16);
    object.add_symbol(object::write::Symbol {
        name: name.to_vec(),
        value: 0,
        size: u64::try_from(size).unwrap(),
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: object::write::SymbolSection::Section(text),
        flags: object::SymbolFlags::None,
    });
    let image = object.write().unwrap();
    let mut builder = build::elf::Builder::read(image.as_slice()).unwrap();
    builder.header.e_type = elf::ET_EXEC;
    let text = builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".text")
        .unwrap();
    text.sh_addr = address;
    let text_id = text.id();
    for symbol in builder
        .symbols
        .iter_mut()
        .filter(|symbol| symbol.section == Some(text_id))
    {
        symbol.st_value += address;
    }
    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    let parsed = object::File::parse(bytes.as_slice()).unwrap();
    assert!(parsed.symbol_table().is_some());
    let text = parsed.section_by_name(".text").unwrap();
    let symbol = parsed
        .symbols()
        .find(|symbol| symbol.name_bytes() == Ok(name))
        .unwrap();
    assert!(symbol.address() >= text.address());
    assert!(symbol.address() + symbol.size() <= text.address() + text.size());
    bytes
}

fn elf_with_dynamic_text_symbol(name: &'static [u8], address: u64, size: usize) -> Vec<u8> {
    let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
    builder.header.e_type = elf::ET_DYN;
    builder.header.e_machine = elf::EM_X86_64;
    builder.header.e_phoff = 0x40;

    let section = builder.sections.add();
    section.name = b".shstrtab"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.data = build::elf::SectionData::SectionString;

    let section = builder.sections.add();
    section.name = b".text"[..].into();
    section.sh_type = elf::SHT_PROGBITS;
    section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
    section.sh_addr = address;
    section.sh_addralign = 16;
    section.data = build::elf::SectionData::Data(vec![0xcc; size].into());
    let text_id = section.id();

    let section = builder.sections.add();
    section.name = b".dynsym"[..].into();
    section.sh_type = elf::SHT_DYNSYM;
    section.sh_flags = u64::from(elf::SHF_ALLOC);
    section.sh_addralign = 8;
    section.data = build::elf::SectionData::DynamicSymbol;
    let dynsym_id = section.id();

    let section = builder.sections.add();
    section.name = b".dynstr"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.sh_flags = u64::from(elf::SHF_ALLOC);
    section.sh_addralign = 1;
    section.data = build::elf::SectionData::DynamicString;
    let dynstr_id = section.id();

    let symbol = builder.dynamic_symbols.add();
    symbol.name = name.into();
    symbol.st_value = address;
    symbol.st_size = u64::try_from(size).expect("fixture size fits in u64");
    symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
    symbol.section = Some(text_id);

    builder.set_section_sizes();

    let segment = builder.segments.add();
    segment.p_type = elf::PT_LOAD;
    segment.p_flags = elf::PF_R | elf::PF_X;
    segment.p_vaddr = address;
    segment.p_paddr = address;
    segment.p_filesz = 0x1000;
    segment.p_memsz = 0x1000;
    segment.p_align = 16;
    segment.append_section(builder.sections.get_mut(text_id));
    segment.append_section(builder.sections.get_mut(dynsym_id));
    segment.append_section(builder.sections.get_mut(dynstr_id));

    let mut bytes = Vec::new();
    builder.write(&mut bytes).expect("write dynamic-symbol ELF");
    bytes
}
use std::fmt::Write as _;
