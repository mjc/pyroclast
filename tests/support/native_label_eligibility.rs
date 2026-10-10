use super::*;

fn assert_parsed_label_pair(source: &[u8], runtime: &[u8], source_name: &str, runtime_name: &str) {
    use object::{ObjectSection as _, read::elf::SectionHeader as _};
    let object::File::Elf64(source) = object::File::parse(source).unwrap() else {
        panic!("source must be ELF64");
    };
    let object::File::Elf64(runtime) = object::File::parse(runtime).unwrap() else {
        panic!("runtime must be ELF64");
    };
    assert!(source.build_id().unwrap().is_some());
    assert_eq!(source.build_id().unwrap(), runtime.build_id().unwrap());
    assert!(source.symbol_table().is_some());
    assert!(source.dynamic_symbol_table().is_none());
    let labels = source.symbols().collect::<Vec<_>>();
    assert_eq!(labels.len(), 1);
    assert!(
        matches!(labels[0].flags(), object::SymbolFlags::Elf { st_info, .. }
        if st_info & 0xf == object::elf::STT_NOTYPE && st_info >> 4 == object::elf::STB_GLOBAL)
    );
    let section = source
        .section_by_index(labels[0].section_index().unwrap())
        .unwrap();
    let selected = runtime.section_by_index(section.index()).unwrap();
    assert_eq!(section.name(), Ok(source_name));
    assert_eq!(selected.name(), Ok(runtime_name));
    assert_eq!(
        section.elf_section_header().sh_type(source.endian()),
        object::elf::SHT_NOBITS
    );
    assert_eq!(
        selected.elf_section_header().sh_type(runtime.endian()),
        object::elf::SHT_PROGBITS
    );
    assert_ne!(
        section.elf_section_header().sh_flags(source.endian()) & u64::from(object::elf::SHF_ALLOC),
        0
    );
    assert_eq!(section.index(), selected.index());
    assert_eq!(section.address(), selected.address());
    assert!(
        section.address() <= 0xffff_ffff_c100_0010
            && 0xffff_ffff_c100_0010 < section.address() + section.size()
    );
}

pub(super) fn label_recording(bytes: &[u8], sample: u64) -> Vec<u8> {
    let header = pyroclast::perfdata::header::parse_header(bytes).unwrap();
    let offset = usize::try_from(header.data_offset).unwrap();
    let mut rewritten = bytes[..offset].to_vec();
    let mut replaced = 0;
    for record in pyroclast::perfdata::records::iter_records(bytes, header).unwrap() {
        let replacement;
        let payload = if record.header.record_type == PERF_RECORD_SAMPLE
            && u64::from_le_bytes(record.payload[..8].try_into().unwrap()) == 0xffff_ffff_8100_0010
        {
            replacement = sample_payload_with_time(
                sample,
                11,
                12,
                1_000_000_001,
                [0xffff_ffff_ffff_ff80, sample],
            );
            replaced += 1;
            replacement.as_slice()
        } else {
            record.payload
        };
        rewritten.extend(record_bytes_with_misc(
            record.header.record_type,
            record.header.misc,
            payload,
        ));
    }
    assert_eq!(replaced, 1);
    let size = u64::try_from(rewritten.len() - offset).unwrap();
    put_u64(&mut rewritten, 48, size);
    rewritten
}

#[test]
fn native_split_debug_label_only_source_uses_runtime_eligibility() {
    use object::ObjectSection as _;

    let (root, recording, cache) = write_native_split_debug_module_fixture();
    let original = std::fs::read(&cache).unwrap();
    let mut builder = object::build::elf::Builder::read(original.as_slice()).unwrap();
    let text = builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".text")
        .unwrap();
    let text_id = text.id();
    assert_eq!(text.sh_type, object::elf::SHT_NOBITS);
    text.name = b".cold".as_slice().into();
    for symbol in &mut builder.symbols {
        symbol.delete = true;
    }
    let label = builder.symbols.add();
    label.name = b"selected_debug_only_label".as_slice().into();
    label.st_value = 0xffff_ffff_c100_0000;
    label.st_size = 0x1000;
    label.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_NOTYPE);
    label.section = Some(text_id);
    let mut debug = Vec::new();
    builder.write(&mut debug).unwrap();
    std::fs::write(&cache, &debug).unwrap();
    let runtime = std::fs::read(root.path().join("a.ko")).unwrap();
    assert_parsed_label_pair(&debug, &runtime, ".cold", ".text");
    let runtime_elf = object::File::parse(runtime.as_slice()).unwrap();
    let debug_elf = object::File::parse(debug.as_slice()).unwrap();
    assert!(runtime_elf.build_id().unwrap().is_some());
    assert_eq!(
        runtime_elf.build_id().unwrap(),
        debug_elf.build_id().unwrap()
    );
    let labels = debug_elf.symbols().collect::<Vec<_>>();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].name(), Ok("selected_debug_only_label"));
    assert!(
        matches!(labels[0].flags(), object::SymbolFlags::Elf { st_info, .. }
        if st_info & 0xf == object::elf::STT_NOTYPE)
    );
    let source = debug_elf
        .section_by_index(labels[0].section_index().unwrap())
        .unwrap();
    let selected = runtime_elf.section_by_index(source.index()).unwrap();
    assert_eq!(source.name(), Ok(".cold"));
    assert_eq!(selected.name(), Ok(".text"));
    assert_eq!(source.address(), selected.address());
    assert!(
        matches!(source.flags(), object::SectionFlags::Elf { sh_flags }
        if sh_flags & u64::from(object::elf::SHF_ALLOC) != 0)
    );
    assert!(
        !runtime_elf
            .symbols()
            .any(|symbol| symbol.name() == Ok("selected_debug_only_label"))
    );
    let bytes = label_recording(&recording, 0xffff_ffff_c100_0010);
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    let (script, stderr, native) = query_native_module_object(root.path());
    assert_eq!(
        script.matches("selected_debug_only_label+0x10").count(),
        1,
        "{script}\n{stderr}"
    );
    assert_eq!(
        script.matches("first+0x10 ([kernel.kallsyms])").count(),
        2,
        "{script}\n{stderr}"
    );
    assert!(
        stderr.contains("symbol__new: selected_debug_only_label "),
        "{stderr}"
    );
    assert!(
        !script.contains("cached_module_object"),
        "native must use label-only debug source: {script}"
    );
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

fn assert_loaded_empty_api_routes(root: &std::path::Path, bytes: &[u8]) {
    use pyroclast::symbols::{
        SelectedObjectResolver, SymbolDsoName, SymbolLookup, SymbolSourceState, SymbolizerKind,
    };
    use std::fmt::Write as _;

    let summary = summarize_perfdata(bytes).unwrap();
    let requests = [
        0xffff_ffff_8100_0010,
        0xffff_ffff_c100_0010,
        0xffff_ffff_c100_0010,
    ]
    .map(|ip| {
        let mapping = summary.mmap_table.resolve_ref(11, ip).unwrap();
        SymbolRequest {
            addr2line_address: None,
            symbol_lookup: SymbolLookup::UserFileOffset(mapping.relative_address),
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
    for backend in [SymbolizerKind::RustAddr2line, SymbolizerKind::Addr2line] {
        let make_resolver = || {
            let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                SelectedObjectResolver::new(&runner, backend),
                &root.join("perf.data"),
                root,
                [],
                &root.join("kallsyms"),
            );
            resolver.initialize_kernel_maps(&summary.mmap_table);
            resolver
        };
        let expected = vec![Some("_stext+0x10".to_string()), None, None];
        assert_eq!(make_resolver().resolve_batch(&requests).unwrap(), expected);
        let resolver = make_resolver();
        let sequential = requests
            .iter()
            .flat_map(|request| {
                resolver
                    .resolve_batch(std::slice::from_ref(request))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(sequential, expected);
        for inline in [false, true] {
            let resolver = make_resolver();
            for (index, request) in requests.iter().enumerate() {
                let result = if inline {
                    resolver.resolve_frame_batch_with_metadata(std::slice::from_ref(request))
                } else {
                    resolver.resolve_base_frame_batch_with_metadata(std::slice::from_ref(request))
                }
                .unwrap();
                if index > 0 {
                    assert!(
                        result[0].frames.is_empty(),
                        "{backend:?} inline={inline}: {result:?}"
                    );
                    assert_eq!(result[0].source_state, SymbolSourceState::AddressDependent);
                    assert_eq!(result[0].kernel_dso, SymbolDsoName::Mapping);
                }
            }
        }
    }
}

#[test]
fn native_split_debug_core_label_rejects_runtime_cold_section() {
    use object::ObjectSection as _;

    let (root, recording, cache) = write_native_split_debug_module_fixture();
    let original = std::fs::read(&cache).unwrap();
    let mut source = object::build::elf::Builder::read(original.as_slice()).unwrap();
    let text = source
        .sections
        .iter()
        .find(|section| section.name.as_slice() == b".text")
        .unwrap();
    assert_eq!(text.sh_type, object::elf::SHT_NOBITS);
    let text_id = text.id();
    for symbol in &mut source.symbols {
        symbol.delete = true;
    }
    let label = source.symbols.add();
    label.name = b"rejected_debug_only_label".as_slice().into();
    label.st_value = 0xffff_ffff_c100_0000;
    label.st_size = 0x1000;
    label.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_NOTYPE);
    label.section = Some(text_id);
    let mut debug = Vec::new();
    source.write(&mut debug).unwrap();
    std::fs::write(&cache, &debug).unwrap();

    let runtime_path = root.path().join("a.ko");
    let original_runtime = std::fs::read(&runtime_path).unwrap();
    let mut runtime = object::build::elf::Builder::read(original_runtime.as_slice()).unwrap();
    runtime
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".text")
        .unwrap()
        .name = b".cold".as_slice().into();
    let mut runtime_bytes = Vec::new();
    runtime.write(&mut runtime_bytes).unwrap();
    std::fs::write(runtime_path, &runtime_bytes).unwrap();
    assert_parsed_label_pair(&debug, &runtime_bytes, ".text", ".cold");
    let runtime_elf = object::File::parse(runtime_bytes.as_slice()).unwrap();
    let debug_elf = object::File::parse(debug.as_slice()).unwrap();
    assert!(runtime_elf.build_id().unwrap().is_some());
    assert_eq!(
        runtime_elf.build_id().unwrap(),
        debug_elf.build_id().unwrap()
    );
    let labels = debug_elf.symbols().collect::<Vec<_>>();
    assert_eq!(labels.len(), 1);
    let source_section = debug_elf
        .section_by_index(labels[0].section_index().unwrap())
        .unwrap();
    let selected = runtime_elf
        .section_by_index(source_section.index())
        .unwrap();
    assert_eq!(source_section.name(), Ok(".text"));
    assert_eq!(selected.name(), Ok(".cold"));
    assert_eq!(source_section.address(), selected.address());
    let bytes = label_recording(&recording, 0xffff_ffff_c100_0010);
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    let (script, stderr, native) = query_native_module_object(root.path());
    assert!(
        !stderr.contains("symbol__new: rejected_debug_only_label "),
        "{script}\n{stderr}"
    );
    assert!(
        !script.contains("rejected_debug_only_label"),
        "{script}\n{stderr}"
    );
    assert_eq!(
        script.matches("ffffffffc1000010").count(),
        3,
        "{script}\n{stderr}"
    );
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

fn write_loaded_empty_pair(root: &std::path::Path, cache: &std::path::Path) {
    let original = std::fs::read(cache).unwrap();
    let mut source = object::build::elf::Builder::read(original.as_slice()).unwrap();
    let text = source
        .sections
        .iter()
        .find(|section| section.name.as_slice() == b".text")
        .unwrap()
        .id();
    for symbol in &mut source.symbols {
        symbol.delete = true;
    }
    let label = source.symbols.add();
    label.name = b"rejected_core_first_label".as_slice().into();
    label.st_value = 0xffff_ffff_c100_0000;
    label.st_size = 0x1000;
    label.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_NOTYPE);
    label.section = Some(text);
    let mut debug = Vec::new();
    source.write(&mut debug).unwrap();
    std::fs::write(cache, &debug).unwrap();
    let path = root.join("a.ko");
    let original = std::fs::read(&path).unwrap();
    let mut runtime = object::build::elf::Builder::read(original.as_slice()).unwrap();
    runtime
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".text")
        .unwrap()
        .name = b".cold".as_slice().into();
    let mut bytes = Vec::new();
    runtime.write(&mut bytes).unwrap();
    std::fs::write(path, &bytes).unwrap();
    assert_parsed_label_pair(&debug, &bytes, ".text", ".cold");
}

fn core_first_recording(bytes: &[u8]) -> Vec<u8> {
    let header = pyroclast::perfdata::header::parse_header(bytes).unwrap();
    let offset = usize::try_from(header.data_offset).unwrap();
    let mut result = bytes[..offset].to_vec();
    let queries = [
        0xffff_ffff_8100_0010,
        0xffff_ffff_c100_0010,
        0xffff_ffff_c100_0010,
    ];
    let mut sample = 0;
    for record in pyroclast::perfdata::records::iter_records(bytes, header).unwrap() {
        let replacement;
        let payload = if record.header.record_type == PERF_RECORD_SAMPLE {
            let ip = queries[sample];
            replacement = sample_payload_with_time(
                ip,
                11,
                12,
                1_000_000_000 + u64::try_from(sample).unwrap(),
                [0xffff_ffff_ffff_ff80, ip],
            );
            sample += 1;
            replacement.as_slice()
        } else {
            record.payload
        };
        result.extend(record_bytes_with_misc(
            record.header.record_type,
            record.header.misc,
            payload,
        ));
    }
    assert_eq!(sample, queries.len());
    let size = u64::try_from(result.len() - offset).unwrap();
    put_u64(&mut result, 48, size);
    result
}

#[test]
fn native_core_first_loaded_empty_module_pair_does_not_restore_kallsyms() {
    let (root, recording, cache) = write_native_split_debug_module_fixture();
    std::fs::remove_file(root.path().join("kcore")).unwrap();
    write_loaded_empty_pair(root.path(), &cache);
    let bytes = core_first_recording(&recording);
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    let kallsyms = std::fs::read_to_string(root.path().join("kallsyms")).unwrap();
    assert!(kallsyms.contains("ffffffffc1000000 T first\t[a]"));
    let (script, stderr, native) = query_native_module_object(root.path());
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert!(
        stderr.contains("no symbols found in"),
        "native loaded the empty selected table: {stderr}"
    );
    assert_eq!(
        script.matches("_stext+0x10").count(),
        1,
        "{script}\n{stderr}"
    );
    assert_eq!(
        script.matches("ffffffffc1000010 [unknown] ([a])").count(),
        2,
        "{script}\n{stderr}"
    );
    assert!(
        !script.contains("rejected_core_first_label"),
        "{script}\n{stderr}"
    );
    assert!(!script.contains("first+0x10"), "{script}\n{stderr}");
    assert!(
        !script.contains("cached_module_object"),
        "{script}\n{stderr}"
    );
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
    assert_loaded_empty_api_routes(root.path(), &bytes);
}
