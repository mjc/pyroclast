// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::Arc;

use object::{Object, ObjectSection, ObjectSymbol, build, elf};

use super::{PerfObjectSymbolIndex, SymbolLookup, elf_with_text_symbol_fixtures};

fn paired_label_sections(runtime_eligible: bool) -> (Vec<u8>, Vec<u8>) {
    let base = elf_with_text_symbol_fixtures(
        elf::EM_X86_64,
        &[(
            b"paired_label",
            0x1000,
            16,
            elf::STB_GLOBAL,
            elf::STT_NOTYPE,
        )],
    );
    let mut source = build::elf::Builder::read(base.as_slice()).expect("source ELF");
    let text = source
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".text")
        .expect("source text");
    text.sh_type = elf::SHT_NOBITS;
    text.data = build::elf::SectionData::UninitializedData(text.sh_size);
    if runtime_eligible {
        text.name = b".cold".as_slice().into();
    }
    source.set_section_sizes();
    let mut source_bytes = Vec::new();
    source.write(&mut source_bytes).expect("write source ELF");

    let mut runtime = build::elf::Builder::read(base.as_slice()).expect("runtime ELF");
    if !runtime_eligible {
        runtime
            .sections
            .iter_mut()
            .find(|section| section.name.as_slice() == b".text")
            .expect("runtime text")
            .name = b".cold".as_slice().into();
    }
    let opd = runtime.sections.add();
    opd.name = b".opd".as_slice().into();
    opd.sh_type = elf::SHT_PROGBITS;
    opd.sh_addralign = 8;
    opd.data = build::elf::SectionData::Data(vec![0; 8].into());
    runtime.set_section_sizes();
    let mut runtime_bytes = Vec::new();
    runtime
        .write(&mut runtime_bytes)
        .expect("write runtime ELF");
    (source_bytes, runtime_bytes)
}

fn assert_paired_label_projection(runtime_eligible: bool) {
    let (source_bytes, runtime_bytes) = paired_label_sections(runtime_eligible);
    let source = object::File::parse(source_bytes.as_slice()).expect("parse source");
    let runtime = object::File::parse(runtime_bytes.as_slice()).expect("parse runtime");
    assert!(!super::super::elf_possibly_runtime(&source));
    assert!(super::super::elf_possibly_runtime(&runtime));
    let raw = source.symbols().next().expect("only source label");
    assert_eq!(source.symbols().count(), 1);
    assert!(super::super::perf_symbol_is_allocated_candidate(
        &source, &raw
    ));
    assert_eq!(
        super::super::perf_symbol_is_candidate(&source, &raw),
        !runtime_eligible
    );
    let source_section = source
        .section_by_index(raw.section_index().unwrap())
        .unwrap();
    let selected = runtime.section_by_index(source_section.index()).unwrap();
    assert_eq!(source_section.address(), selected.address());
    assert_eq!(
        super::super::elf_section_layout(&source, source_section.index())
            .unwrap()
            .0,
        elf::SHT_NOBITS
    );
    assert_eq!(selected.name().unwrap().contains("text"), runtime_eligible);
    let (_, file_offset) = super::super::elf_section_layout(&runtime, selected.index()).unwrap();
    let (_, source_offset) =
        super::super::elf_section_layout(&source, source_section.index()).unwrap();
    let section = u32::try_from(selected.index().0).expect("fixture section index");
    let index = PerfObjectSymbolIndex::from_object_bytes(&source_bytes);
    let projection = Arc::new(super::super::kernel_module_symbol_projection(
        &source,
        &runtime,
        super::super::kernel_module_max_text_offset(&runtime),
    ));
    index.register_kernel_module_projection(1, projection);
    let lookup = index.candidate_for_lookup(
        SymbolLookup::KernelModuleSection {
            projection: 1,
            section,
            offset: file_offset + 8,
        },
        0,
    );
    assert_eq!(
        lookup.map(|(symbol, start, query)| (symbol.name.as_str(), query - start)),
        runtime_eligible.then_some(("paired_label", 8))
    );
    let user = index.candidate_for_lookup(SymbolLookup::UserFileOffset(source_offset + 8), 0);
    assert_eq!(
        user.map(|(symbol, _, _)| symbol.name.as_str()),
        (!runtime_eligible).then_some("paired_label")
    );
    let kernel = index.candidate_for_lookup(
        SymbolLookup::KernelSection {
            section,
            offset: source_offset + 8,
        },
        0,
    );
    assert_eq!(
        kernel.map(|(symbol, _, _)| symbol.name.as_str()),
        (!runtime_eligible).then_some("paired_label")
    );
    assert_eq!(index.bfd_function_record_name(0x1008), Some("paired_label"));
}

#[test]
fn module_projection_accepts_source_cold_label_in_runtime_text() {
    assert_paired_label_projection(true);
}

#[test]
fn module_projection_rejects_source_text_label_in_runtime_cold() {
    assert_paired_label_projection(false);
}

#[test]
fn paired_label_availability_is_per_request_in_mixed_retained_batches() {
    use super::super::{RustAddr2lineResolver, SymbolResolver, SymbolSourceState};

    let (source_bytes, runtime_text) = paired_label_sections(true);
    let (_, runtime_cold) = paired_label_sections(false);
    let root = tempfile::tempdir().unwrap();
    let source_path = root.path().join("source.debug");
    let text_path = root.path().join("text.ko");
    let cold_path = root.path().join("cold.ko");
    std::fs::write(&source_path, &source_bytes).unwrap();
    std::fs::write(&text_path, &runtime_text).unwrap();
    std::fs::write(&cold_path, &runtime_cold).unwrap();
    let resolver = RustAddr2lineResolver::new();
    let mut text_request = super::test_request(text_path.to_str().unwrap(), 0x1008);
    let text_metadata = resolver
        .selected_object_module_metadata(&source_path, &text_request)
        .unwrap();
    text_request.path.clone_from(&source_path);
    let object = object::File::parse(runtime_text.as_slice()).unwrap();
    let text = object.section_by_name(".text").unwrap();
    let (_, text_offset) = super::super::elf_section_layout(&object, text.index()).unwrap();
    let section = u32::try_from(text.index().0).expect("fixture section index");
    text_request.symbol_lookup = SymbolLookup::KernelModuleSection {
        projection: text_metadata.lookup_projection.unwrap(),
        section,
        offset: text_offset + 8,
    };

    let mut cold_request = super::test_request(cold_path.to_str().unwrap(), 0x1008);
    let cold_metadata = resolver
        .selected_object_module_metadata(&source_path, &cold_request)
        .unwrap();
    let cold_projection = cold_metadata.lookup_projection.unwrap();
    cold_request.path.clone_from(&source_path);
    let object = object::File::parse(runtime_cold.as_slice()).unwrap();
    let cold = object.section_by_name(".cold").unwrap();
    let (_, cold_offset) = super::super::elf_section_layout(&object, cold.index()).unwrap();
    cold_request.symbol_lookup = SymbolLookup::KernelModuleSection {
        projection: cold_projection,
        section,
        offset: cold_offset + 8,
    };
    assert_ne!(
        cold_metadata.lookup_projection,
        text_metadata.lookup_projection
    );
    let mut user_request = super::test_request(source_path.to_str().unwrap(), 0x1008);
    let source = object::File::parse(source_bytes.as_slice()).unwrap();
    let (_, source_offset) = super::super::elf_section_layout(&source, cold.index()).unwrap();
    user_request.symbol_lookup = SymbolLookup::UserFileOffset(source_offset + 8);
    let mut gap_request = text_request.clone();
    gap_request.symbol_lookup = SymbolLookup::KernelModuleSection {
        projection: text_metadata.lookup_projection.unwrap(),
        section,
        offset: text_offset + 32,
    };
    let mut foreign_request = gap_request.clone();
    foreign_request.symbol_lookup = SymbolLookup::KernelModuleSection {
        projection: cold_projection.checked_add(1).unwrap(),
        section,
        offset: cold_offset + 8,
    };
    let requests = [
        user_request,
        text_request,
        cold_request,
        gap_request,
        foreign_request,
    ];
    std::fs::remove_file(&source_path).unwrap();
    std::fs::remove_file(&text_path).unwrap();
    std::fs::remove_file(&cold_path).unwrap();
    for order in [[0, 1, 2, 3, 4], [2, 4, 3, 1, 0]] {
        let batch = order.map(|index| requests[index].clone());
        for resolved in [
            resolver
                .resolve_base_frame_batch_with_metadata(&batch)
                .unwrap(),
            resolver.resolve_frame_batch_with_metadata(&batch).unwrap(),
        ] {
            for (index, result) in order.into_iter().zip(resolved) {
                assert_eq!(
                    result.source_state,
                    if index == 0 || index == 4 {
                        SymbolSourceState::Unavailable
                    } else {
                        SymbolSourceState::AddressDependent
                    },
                    "request {index}"
                );
                assert_eq!(
                    result.frames,
                    if index == 1 {
                        vec!["paired_label+0x8".to_string()]
                    } else {
                        Vec::new()
                    },
                    "request {index}"
                );
            }
        }
    }
}

#[test]
fn rejected_user_labels_do_not_open_plt_synthesis_gate() {
    let base = super::plt_regressions::elf_with_allocated_plt(
        &[(b"cold_label", 0x1000, 16, elf::STB_GLOBAL, elf::STT_NOTYPE)],
        0x9000,
        16,
    );
    let mut builder = build::elf::Builder::read(base.as_slice()).unwrap();
    builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".text")
        .unwrap()
        .name = b".cold".as_slice().into();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    assert!(super::super::perf_symbol_is_allocated_candidate(
        &object,
        &object.symbols().next().unwrap()
    ));
    assert!(!super::super::perf_symbol_is_candidate(
        &object,
        &object.symbols().next().unwrap()
    ));
    let (_, offset) =
        super::super::elf_section_layout(&object, object.section_by_name(".plt").unwrap().index())
            .unwrap();
    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    assert!(
        index
            .candidate_for_lookup(SymbolLookup::UserFileOffset(offset + 8), 0)
            .is_none()
    );
    assert_eq!(index.bfd_function_record_name(0x1008), Some("cold_label"));
}

#[test]
fn user_plt_ifunc_fallback_does_not_admit_kernel_only_label() {
    let base = super::plt_regressions::elf_with_mixed_plt_relocations();
    let mut builder = build::elf::Builder::read(base.as_slice()).unwrap();
    let cold = builder.sections.add();
    cold.name = b".cold".as_slice().into();
    cold.sh_type = elf::SHT_NOBITS;
    cold.sh_flags = u64::from(elf::SHF_ALLOC);
    cold.sh_addr = 0x1000;
    cold.sh_addralign = 16;
    cold.data = build::elf::SectionData::UninitializedData(16);
    let cold_id = cold.id();
    let label = builder.symbols.add();
    label.name = b"kernel_only_label_longer_than_function".as_slice().into();
    label.set_st_info(elf::STB_GLOBAL, elf::STT_NOTYPE);
    label.section = Some(cold_id);
    label.st_value = 0x1000;
    label.st_size = 16;
    let relocation = builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".rela.plt")
        .unwrap();
    let build::elf::SectionData::DynamicRelocation(entries) = &mut relocation.data else {
        panic!("structured dynamic relocation table");
    };
    entries[0].symbol = None;
    entries[0].r_type = elf::R_X86_64_IRELATIVE;
    entries[0].r_addend = 0x1000;
    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let cold_label = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("kernel_only_label_longer_than_function"))
        .unwrap();
    assert!(super::super::perf_symbol_is_allocated_candidate(
        &object,
        &cold_label
    ));
    assert!(!super::super::perf_symbol_is_candidate(
        &object,
        &cold_label
    ));
    let (_, offset) =
        super::super::elf_section_layout(&object, object.section_by_name(".plt").unwrap().index())
            .unwrap();
    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    assert_eq!(
        index
            .candidate_for_lookup(SymbolLookup::UserFileOffset(offset + 16), 0)
            .map(|(symbol, _, _)| symbol.name.as_str()),
        Some("regular_function@plt")
    );
}
