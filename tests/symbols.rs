use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use object::{Object, ObjectSegment, ObjectSymbol, SymbolKind, build, elf};
use proptest::prelude::*;
use pyroclast::cli::SymbolizerKind;
use pyroclast::perfdata::mappings::FileIdentity;
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};
use pyroclast::symbols::{
    Addr2lineResolver, Kallsyms, RustAddr2lineResolver, SymbolCache, SymbolRequest, SymbolResolver,
    more_specific_dwarf_name_from_debug_strings, perf_debug_dir,
    perf_dwarf_frame_names_from_object, perf_dwarf_frame_names_from_object_bytes,
    perf_dwarf_function_name, perf_inline_frame_order, perf_symbol_name,
    perf_symbol_resolver_for_perfdata_file,
    perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources,
    perf_symbol_resolver_for_perfdata_file_with_symbolizer,
};

fn test_symbol_request(path_index: u8, relative_address: u16) -> SymbolRequest {
    SymbolRequest {
        path: PathBuf::from(format!("/bin/app{}", path_index % 4)),
        relative_address: u64::from(relative_address),
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
            path: object_path,
            relative_address: 0x1008,
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
        perf_symbol_name(
            "alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next"
        ),
        "dying_next<u64, alloc::string::String, alloc::alloc::Global>"
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
            "pyroclast::symbols::perf_symbol_resolver_for_current_home_with_symbolizer<pyroclast::process::RealCommandRunner>"
        ),
        "perf_symbol_resolver_for_current_home_with_symbolizer<pyroclast::process::RealCommandRunner>"
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
        perf_dwarf_function_name(
            "alloc::collections::btree::map::BTreeMap<u64, alloc::string::String, alloc::alloc::Global>::insert"
        ),
        "insert<u64, alloc::string::String, alloc::alloc::Global>"
    );
    assert_eq!(
        perf_dwarf_function_name(
            "alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next"
        ),
        "dying_next<u64, alloc::string::String, alloc::alloc::Global>"
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
}

#[test]
fn finds_unique_generic_dwarf_names_from_debug_strings() {
    let debug_strings = b"\0pyroclast::symbols::perf_symbol_resolver_for_current_home_with_symbolizer<pyroclast::process::RealCommandRunner>\0other_name\0";

    assert_eq!(
        more_specific_dwarf_name_from_debug_strings(
            "perf_symbol_resolver_for_current_home_with_symbolizer",
            debug_strings
        ),
        Some(
            "perf_symbol_resolver_for_current_home_with_symbolizer<pyroclast::process::RealCommandRunner>"
                .to_string()
        )
    );
}

#[test]
fn specializes_generic_placeholder_dwarf_names_from_debug_strings() {
    let debug_strings = b"\0alloc::collections::btree::map::BTreeMap<u64, alloc::string::String, alloc::alloc::Global>::insert\0other_name\0";

    assert_eq!(
        more_specific_dwarf_name_from_debug_strings("insert<K,V,A>", debug_strings),
        Some("insert<u64, alloc::string::String, alloc::alloc::Global>".to_string())
    );
}

#[test]
fn specializes_qualified_generic_placeholder_dwarf_names_from_debug_strings() {
    let debug_strings = b"\0alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next\0other_name\0";

    assert_eq!(
        more_specific_dwarf_name_from_debug_strings(
            "alloc::collections::btree::map::IntoIter<K,V,A>::dying_next",
            debug_strings
        ),
        Some("dying_next<u64, alloc::string::String, alloc::alloc::Global>".to_string())
    );
}

#[test]
fn perf_dwarf_frame_names_prefer_die_names_like_perf_script() {
    let Some((profiling_binary, object_bytes)) = profiling_binary_fixture() else {
        return;
    };
    let Some(address) = text_symbol_addresses(&object_bytes)
        .into_iter()
        .find(|address| {
            let Some(frames) = perf_dwarf_frame_names_from_object_bytes(&object_bytes, *address)
            else {
                return false;
            };
            let Some(expected) =
                external_addr2line_frames_leaf_to_root(&profiling_binary, *address)
            else {
                return false;
            };
            frames.len() == expected.len()
                && frames.iter().zip(expected.iter()).any(|(frame, external)| {
                    frame != external && frame.contains('<') && !external.contains('<')
                })
        })
    else {
        return;
    };

    let frames =
        perf_dwarf_frame_names_from_object(&profiling_binary, address).expect("perf dwarf frames");
    let expected = external_addr2line_frames_leaf_to_root(&profiling_binary, address)
        .expect("external addr2line frames");

    assert_eq!(frames.len(), expected.len());
    assert!(frames.iter().zip(expected.iter()).any(|(frame, external)| {
        frame != external && frame.contains('<') && !external.contains('<')
    }));
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
            path: profiling_binary.clone(),
            relative_address: address,
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
            path: profiling_binary.clone(),
            relative_address: address,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve frames");

    let expected = external_addr2line_frames_root_to_leaf(&profiling_binary, address)
        .expect("external addr2line frames");

    assert_eq!(frames, vec![expected]);
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
            path: profiling_binary,
            relative_address: address,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("resolve symbols");

    assert_eq!(symbols, vec![Some(expected_symbol.clone())]);
}

fn profiling_binary_fixture() -> Option<(PathBuf, Vec<u8>)> {
    let profiling_binary = PathBuf::from("target/profiling/pyroclast");
    let bytes = std::fs::read(&profiling_binary).ok()?;
    Some((profiling_binary, bytes))
}

fn find_profiling_address(
    object_bytes: &[u8],
    predicate: impl Fn(&[String]) -> bool,
) -> Option<u64> {
    text_symbol_addresses(object_bytes)
        .into_iter()
        .find(|address| {
            perf_dwarf_frame_names_from_object_bytes(object_bytes, *address)
                .is_some_and(|frames| predicate(&frames))
        })
}

fn text_symbol_addresses(object_bytes: &[u8]) -> Vec<u64> {
    let object = object::File::parse(object_bytes).expect("object file");
    let mut addresses = object
        .symbols()
        .filter(|symbol| symbol.address() != 0 && symbol.kind() == SymbolKind::Text)
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
            path: profiling_binary.to_path_buf(),
            relative_address: *address,
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

#[test]
fn rejects_ambiguous_generic_dwarf_names_from_debug_strings() {
    let debug_strings =
        b"\0crate::make<crate::A>\0other::make<other::B>\0crate::not_make<crate::A>\0";

    assert_eq!(
        more_specific_dwarf_name_from_debug_strings("make", debug_strings),
        None
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
fn kallsyms_parse_modules_only_keeps_module_symbols() {
    let symbols = Kallsyms::parse_modules(
        "\
ffffffff81001280 T asm_exc_page_fault
ffffffffc0e17dae t zfs_read [zfs]
ffffffffc0e17e10 t zfs_write [zfs]
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
fn kallsyms_parse_modules_for_path_only_keeps_requested_module() {
    let symbols = Kallsyms::parse_modules_for_path(
        "\
ffffffff81001280 T asm_exc_page_fault
ffffffffc0e17dae t zfs_read [zfs]
ffffffffc0e17e10 t zfs_write [zfs]
ffffffffc1e17dae t igb_clean_rx_irq [igb]
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

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: 0xffff_ffff_8800_008f,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![None]);
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
fn perf_symbol_resolver_prefers_system_map_over_live_kallsyms_for_vmlinux() {
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
            path: PathBuf::from("[kernel.kallsyms]"),
            relative_address: 0xffff_ffff_8469_97ac,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("__pi_memcpy".to_string())]);
}

#[test]
fn perf_symbol_resolver_loads_live_kallsyms_lazily_for_modules() {
    let root = tempfile::tempdir().expect("root");
    let live_kallsyms = root.path().join("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_kallsyms_from_path(&live_kallsyms);

    std::fs::write(
        &live_kallsyms,
        "\
ffffffff846997a0 T __pi_memcpy
ffffffffc0e17dae t zfs_read [zfs]
",
    )
    .expect("kallsyms");

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: PathBuf::from("[zfs]"),
            relative_address: 0xffff_ffff_c0e1_7dae,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("zfs_read".to_string())]);
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_uses_a_single_live_kallsyms_snapshot_for_module_paths() {
    let root = tempfile::tempdir().expect("root");
    let live_kallsyms = root.path().join("kallsyms");

    let runner = Addr2lineRunner::new(b"");
    let resolver = pyroclast::symbols::PerfSymbolResolver::new(&runner)
        .with_system_kallsyms_from_path(&live_kallsyms);

    std::fs::write(
        &live_kallsyms,
        "\
ffffffff846997a0 T __pi_memcpy
ffffffffc0e17dae t zfs_read [zfs]
ffffffffc1e17dae t igb_clean_rx_irq [igb]
",
    )
    .expect("kallsyms");

    let zfs = SymbolRequest {
        path: PathBuf::from("[zfs]"),
        relative_address: 0xffff_ffff_c0e1_7dae,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let symbols = resolver
        .resolve_batch(std::slice::from_ref(&zfs))
        .expect("symbols");
    assert_eq!(symbols, vec![Some("zfs_read".to_string())]);

    std::fs::write(
        &live_kallsyms,
        "\
ffffffff846997a0 T __pi_memcpy
ffffffffc2e17dae t unrelated_module_symbol [mlx5]
",
    )
    .expect("kallsyms");

    let igb = SymbolRequest {
        path: PathBuf::from("[igb]"),
        relative_address: 0xffff_ffff_c1e1_7dae,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    let symbols = resolver.resolve_batch(&[zfs, igb]).expect("symbols");

    assert_eq!(
        symbols,
        vec![
            Some("zfs_read".to_string()),
            Some("igb_clean_rx_irq".to_string())
        ]
    );
    assert!(runner.commands().is_empty());
}

#[test]
fn perf_symbol_resolver_loads_system_map_lazily() {
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
fn perf_symbol_resolver_translates_live_object_file_offsets_to_virtual_addresses() {
    let path = std::env::current_exe().expect("current test binary");
    let bytes = std::fs::read(&path).expect("current test binary bytes");
    let object = object::File::parse(bytes.as_slice()).expect("current test binary object");
    let (file_offset, virtual_address) = object
        .segments()
        .find_map(|segment| {
            let (file_offset, file_size) = segment.file_range();
            let virtual_address = segment.address();
            (file_size > 8 && virtual_address != file_offset)
                .then_some((file_offset + 8, virtual_address + 8))
        })
        .expect("current test binary has a biased load segment");
    let object_resolver = RecordingResolver::with_symbols([(
        SymbolRequest {
            path: path.clone(),
            relative_address: virtual_address,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        },
        "app::main".to_string(),
    )]);
    let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(object_resolver);

    let symbols = resolver
        .resolve_batch(&[SymbolRequest {
            path: path.clone(),
            relative_address: file_offset,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }])
        .expect("symbols");

    assert_eq!(symbols, vec![Some("app::main".to_string())]);
    assert_eq!(
        resolver.object_resolver().batch_calls(),
        vec![vec![SymbolRequest {
            path,
            relative_address: virtual_address,
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
fn perf_symbol_resolver_uses_live_user_object_despite_recorded_identity_mismatch_like_perf() {
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

    assert_eq!(symbols, vec![Some("app::main".to_string())]);
    assert_eq!(
        resolver.object_resolver().batch_calls(),
        vec![vec![SymbolRequest {
            path: object_path.path().to_path_buf(),
            relative_address: 0x10,
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

#[test]
fn perf_symbol_resolver_keeps_live_kallsyms_for_modules_when_system_map_exists() {
    let home = tempfile::tempdir().expect("home");
    let perfdata = home.path().join("perf.data");
    std::fs::write(&perfdata, perfdata_with_kernel_build_id()).expect("perfdata");
    let system_map = home.path().join("System.map");
    std::fs::write(&system_map, "ffffffff81001280 T asm_exc_page_fault\n").expect("system map");
    let kallsyms = home.path().join("kallsyms");
    std::fs::write(&kallsyms, "ffffffffc0e17dae t zfs_read\t[zfs]\n").expect("kallsyms");

    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        RecordingResolver::default(),
        &perfdata,
        home.path(),
        [system_map],
        &kallsyms,
    );

    let symbols = resolver
        .resolve_batch(&[
            SymbolRequest {
                path: PathBuf::from("[kernel.kallsyms]_text"),
                relative_address: 0xffff_ffff_8100_1280,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                path: PathBuf::from("[zfs]"),
                relative_address: 0xffff_ffff_c0e1_7dae,
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
            Some("zfs_read".to_string())
        ]
    );
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
