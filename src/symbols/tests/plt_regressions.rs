// SPDX-License-Identifier: Apache-2.0 OR MIT

use object::{Object, ObjectSection, ObjectSegment, build, elf};

use super::{PerfObjectSymbolIndex, SymbolLookup, elf_with_text_symbol_fixtures};

pub(super) fn elf_with_allocated_plt(
    symbols: &[(&'static [u8], u64, u64, u8, u8)],
    plt_address: u64,
    plt_size: usize,
) -> Vec<u8> {
    let base = elf_with_text_symbol_fixtures(elf::EM_X86_64, symbols);
    let mut builder = build::elf::Builder::read(base.as_slice()).expect("read symbol fixture ELF");
    builder.header.e_phoff = 0x40;
    let text = builder
        .sections
        .iter()
        .find(|section| section.name.as_slice() == b".text")
        .expect("text section")
        .id();
    let plt = builder.sections.add();
    plt.name = b".plt"[..].into();
    plt.sh_type = elf::SHT_PROGBITS;
    plt.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
    plt.sh_addr = plt_address;
    plt.sh_addralign = 16;
    plt.data = build::elf::SectionData::Data(vec![0; plt_size].into());
    let plt_id = plt.id();

    let segment = builder.segments.add();
    segment.p_type = elf::PT_LOAD;
    segment.p_flags = elf::PF_R | elf::PF_X;
    segment.p_offset = 0x1000;
    segment.p_vaddr = 0x1000;
    segment.p_paddr = 0x1000;
    segment.p_filesz = 0;
    segment.p_memsz = 0;
    segment.p_align = 16;
    let text_section = builder
        .sections
        .iter_mut()
        .find(|section| section.id() == text)
        .expect("text section by retained ID");
    segment.append_section(text_section);
    let text_end = builder
        .sections
        .iter()
        .find(|section| section.id() == text)
        .map(|section| section.sh_offset + section.sh_size)
        .expect("appended text section file range");
    builder
        .sections
        .iter_mut()
        .find(|section| section.id() == plt_id)
        .expect("PLT section by retained ID")
        .sh_offset = (text_end + 15) & !15;

    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).expect("write PLT fixture ELF");

    let object = object::File::parse(bytes.as_slice()).expect("parse PLT fixture ELF");
    assert_eq!(object.segments().count(), 1);
    let text = object.section_by_name(".text").expect("text section");
    let load = object.segments().next().expect("load segment");
    assert_eq!(text.address(), load.address());
    assert!(object.section_by_name(".rela.plt").is_none());
    assert!(object.section_by_name(".rel.plt").is_none());
    let plt = object
        .section_by_name(".plt")
        .expect("allocated PLT section");
    let text = object.section_by_name(".text").expect("text section");
    assert!(
        plt.file_range().expect("PLT file range").0
            >= text.file_range().expect("text file range").0 + text.size()
    );
    let load = object.segments().next().expect("text load segment");
    let (load_offset, load_file_size) = load.file_range();
    let plt_offset = plt.file_range().expect("PLT file range").0;
    assert!(
        plt_offset < load_offset || plt_offset >= load_offset + load_file_size,
        "PLT file offset must be outside the text PT_LOAD"
    );
    assert_eq!(plt.address(), plt_address);
    assert_eq!(plt.size(), plt_size as u64);
    assert!(matches!(
        plt.flags(),
        object::SectionFlags::Elf { sh_flags }
            if sh_flags & u64::from(elf::SHF_ALLOC) != 0
    ));
    assert!(
        object
            .segments()
            .all(|segment| !(plt.address() >= segment.address()
                && plt.address() < segment.address() + segment.size()))
    );
    bytes
}

pub(super) fn elf_with_mixed_plt_relocations() -> Vec<u8> {
    let base = elf_with_text_symbol_fixtures(
        elf::EM_X86_64,
        &[(
            b"regular_function",
            0x1000,
            16,
            elf::STB_GLOBAL,
            elf::STT_FUNC,
        )],
    );
    let mut builder = build::elf::Builder::read(base.as_slice()).expect("read PLT fixture ELF");
    builder.header.e_phoff = 0x40;
    let text_id = builder
        .sections
        .iter()
        .find(|section| section.name.as_slice() == b".text")
        .expect("text section")
        .id();

    let plt = builder.sections.add();
    plt.name = b".plt"[..].into();
    plt.sh_type = elf::SHT_PROGBITS;
    plt.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
    plt.sh_addr = 0x9000;
    plt.sh_addralign = 16;
    plt.data = build::elf::SectionData::Data(vec![0; 16].into());
    let plt_id = plt.id();

    let dynstr = builder.sections.add();
    dynstr.name = b".dynstr"[..].into();
    dynstr.sh_type = elf::SHT_STRTAB;
    dynstr.sh_flags = u64::from(elf::SHF_ALLOC);
    dynstr.sh_addralign = 1;
    dynstr.data = build::elf::SectionData::DynamicString;
    let dynstr_id = dynstr.id();

    let dynsym = builder.sections.add();
    dynsym.name = b".dynsym"[..].into();
    dynsym.sh_type = elf::SHT_DYNSYM;
    dynsym.sh_flags = u64::from(elf::SHF_ALLOC);
    dynsym.sh_addralign = 8;
    dynsym.data = build::elf::SectionData::DynamicSymbol;
    dynsym.sh_link_section = Some(dynstr_id);
    let dynsym_id = dynsym.id();

    let dynamic_symbol = builder.dynamic_symbols.add();
    dynamic_symbol.name = b"regular_function"[..].into();
    dynamic_symbol.st_value = 0x1000;
    dynamic_symbol.st_size = 16;
    dynamic_symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
    dynamic_symbol.section = Some(text_id);
    let dynamic_symbol_id = dynamic_symbol.id();

    let rela = builder.sections.add();
    rela.name = b".rela.plt"[..].into();
    rela.sh_type = elf::SHT_RELA;
    rela.sh_flags = u64::from(elf::SHF_ALLOC);
    rela.sh_addralign = 8;
    rela.sh_entsize = 24;
    rela.sh_link_section = Some(dynsym_id);
    rela.data = build::elf::SectionData::DynamicRelocation(vec![
        build::elf::DynamicRelocation {
            r_offset: 0x7000,
            symbol: Some(dynamic_symbol_id),
            r_type: elf::R_X86_64_JUMP_SLOT,
            r_addend: 0,
        },
        build::elf::DynamicRelocation {
            r_offset: 0x7010,
            symbol: None,
            r_type: elf::R_X86_64_NONE,
            r_addend: 0,
        },
    ]);
    let rela_id = rela.id();

    builder.set_section_sizes();
    let segment = builder.segments.add();
    segment.p_type = elf::PT_LOAD;
    segment.p_flags = elf::PF_R | elf::PF_X;
    segment.p_offset = 0x1000;
    segment.p_vaddr = 0x1000;
    segment.p_paddr = 0x1000;
    segment.p_align = 16;
    for section_id in [text_id, dynstr_id, dynsym_id, rela_id] {
        segment.append_section(builder.sections.get_mut(section_id));
    }
    let plt_file_offset = (segment.p_offset + segment.p_filesz + 15) & !15;
    builder
        .sections
        .iter_mut()
        .find(|section| section.id() == plt_id)
        .expect("PLT section")
        .sh_offset = plt_file_offset;

    let mut bytes = Vec::new();
    builder
        .write(&mut bytes)
        .expect("write mixed-relocation PLT ELF");
    bytes
}

fn candidate_at_file_offset(index: &PerfObjectSymbolIndex, offset: u64) -> Option<&str> {
    index
        .candidate_for_lookup(SymbolLookup::UserFileOffset(offset), 0)
        .map(|(candidate, _, _)| candidate.name.as_str())
}

fn elf_with_null_symbol_plt_relocations(empty_strings: bool) -> Vec<u8> {
    let original = elf_with_mixed_plt_relocations();
    let object = object::File::parse(original.as_slice()).expect("parse original ELF");
    let mut relocations = object
        .section_by_name(".rela.plt")
        .expect("original relocations")
        .data()
        .expect("raw relocation bytes")
        .to_vec();
    for entry in relocations.as_chunks_mut::<24>().0 {
        entry[12..16].copy_from_slice(&0_u32.to_le_bytes());
    }
    let mut builder = build::elf::Builder::read(original.as_slice()).expect("read original ELF");
    for symbol in &mut builder.dynamic_symbols {
        symbol.delete = true;
    }
    for section in &mut builder.sections {
        section.data = match section.name.as_slice() {
            b".dynstr" => build::elf::SectionData::Data(
                if empty_strings { Vec::new() } else { vec![0] }.into(),
            ),
            b".dynsym" => build::elf::SectionData::Data(vec![0; 24].into()),
            b".rela.plt" => build::elf::SectionData::Data(relocations.clone().into()),
            _ => continue,
        };
    }
    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).expect("write null-symbol ELF");
    bytes
}

#[test]
fn plt_relocations_with_empty_linked_strings_retain_header_without_entries() {
    use object::ObjectSymbol as _;
    use object::read::elf::SectionHeader as _;

    for empty_strings in [false, true] {
        let bytes = elf_with_null_symbol_plt_relocations(empty_strings);
        let object = object::File::parse(bytes.as_slice()).expect("parse null-symbol ELF");
        let object::File::Elf64(elf64) = &object else {
            panic!("fixture must be ELF64");
        };
        let dynstr = elf64.section_by_name(".dynstr").expect("dynamic strings");
        let dynsym = elf64.section_by_name(".dynsym").expect("dynamic symbols");
        let rela = elf64.section_by_name(".rela.plt").expect("PLT relocations");
        assert_eq!(
            dynstr.elf_section_header().sh_type(elf64.endian()),
            elf::SHT_STRTAB
        );
        assert_eq!(
            dynstr.data().expect("dynamic string bytes").is_empty(),
            empty_strings
        );
        assert_eq!(dynstr.size(), u64::from(!empty_strings));
        assert_eq!(
            dynsym.elf_section_header().sh_type(elf64.endian()),
            elf::SHT_DYNSYM
        );
        assert_eq!(dynsym.data().expect("null symbol row"), &[0; 24]);
        assert_eq!(
            dynsym.elf_section_header().sh_link(elf64.endian()),
            u32::try_from(dynstr.index().0).expect("fixture dynstr section index")
        );
        assert!(object.dynamic_symbol_table().is_some());
        assert_eq!(
            rela.elf_section_header().sh_type(elf64.endian()),
            elf::SHT_RELA
        );
        assert_eq!(
            rela.elf_section_header().sh_link(elf64.endian()),
            u32::try_from(dynsym.index().0).expect("fixture dynsym section index")
        );
        assert_eq!(rela.elf_section_header().sh_entsize(elf64.endian()), 24);
        assert_eq!(rela.size(), 48);
        let raw = rela.data().expect("raw relocation slots");
        assert_eq!(raw.len(), 48);
        for entry in raw.as_chunks::<24>().0 {
            assert_eq!(u32::from_le_bytes(entry[12..16].try_into().unwrap()), 0);
        }
        assert!(
            object
                .symbols()
                .any(|symbol| symbol.name() == Ok("regular_function")
                    && symbol.kind() == object::SymbolKind::Text)
        );
        assert!(
            !object
                .section_by_name(".strtab")
                .expect("regular strings")
                .data()
                .unwrap()
                .is_empty()
        );
        let plt = object.section_by_name(".plt").expect("PLT section");
        assert_eq!(plt.size(), 16);
        let plt_offset = plt.file_range().expect("PLT file range").0;
        let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
        assert_eq!(index.symbol_name(0x1008), Some("regular_function"));
        assert_eq!(
            candidate_at_file_offset(&index, plt_offset + 8),
            Some(".plt")
        );
        for slot in [16, 32] {
            let fallback = format!("offset_{:#x}@plt", plt_offset + slot);
            assert_eq!(
                candidate_at_file_offset(&index, plt_offset + slot),
                (!empty_strings).then_some(fallback.as_str()),
                "empty linked strings: {empty_strings}, slot: {slot}"
            );
        }
    }
}

#[test]
fn zero_size_allocated_plt_outside_load_segments_retains_header() {
    let bytes = elf_with_allocated_plt(
        &[(
            b"regular_function",
            0x1000,
            16,
            elf::STB_GLOBAL,
            elf::STT_FUNC,
        )],
        0x9000,
        0,
    );
    let object = object::File::parse(bytes.as_slice()).expect("parse fixture");
    let plt_offset = object
        .section_by_name(".plt")
        .expect("PLT section")
        .file_range()
        .expect("PLT file range")
        .0;

    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    assert_eq!(candidate_at_file_offset(&index, plt_offset), Some(".plt"));
    assert_eq!(index.symbol_name(0x1008), Some("regular_function"));
}

#[test]
fn nonempty_plt_without_accepted_symbol_rows_has_no_synthetic_header() {
    let bytes = elf_with_allocated_plt(
        &[(b"unit.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE)],
        0x9000,
        16,
    );
    let object = object::File::parse(bytes.as_slice()).expect("parse fixture");
    let plt_offset = object
        .section_by_name(".plt")
        .expect("PLT section")
        .file_range()
        .expect("PLT file range")
        .0;

    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    assert!(index.candidates.is_empty());
    assert_eq!(candidate_at_file_offset(&index, plt_offset), None);
}

#[test]
fn same_nonempty_plt_with_accepted_function_retains_synthetic_header() {
    let bytes = elf_with_allocated_plt(
        &[(
            b"regular_function",
            0x1000,
            16,
            elf::STB_GLOBAL,
            elf::STT_FUNC,
        )],
        0x9000,
        16,
    );
    let object = object::File::parse(bytes.as_slice()).expect("parse fixture");
    let plt_offset = object
        .section_by_name(".plt")
        .expect("PLT section")
        .file_range()
        .expect("PLT file range")
        .0;

    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    assert_eq!(candidate_at_file_offset(&index, plt_offset), Some(".plt"));
    assert_eq!(index.symbol_name(0x1008), Some("regular_function"));
}

#[test]
fn plt_header_uses_raw_relocation_count_with_unsupported_entry() {
    use object::ObjectSymbol as _;
    use object::read::elf::SectionHeader as _;

    let bytes = elf_with_mixed_plt_relocations();
    let object = object::File::parse(bytes.as_slice()).expect("parse mixed-relocation ELF");
    let object::File::Elf64(elf64) = &object else {
        panic!("fixture must be ELF64");
    };
    let dynstr = elf64.section_by_name(".dynstr").expect("dynamic strings");
    let dynsym = elf64.section_by_name(".dynsym").expect("dynamic symbols");
    let rela = elf64.section_by_name(".rela.plt").expect("PLT relocations");
    let dynsym_header = dynsym.elf_section_header();
    let rela_header = rela.elf_section_header();
    assert_eq!(dynsym_header.sh_type(elf64.endian()), elf::SHT_DYNSYM);
    assert_eq!(
        dynsym_header.sh_link(elf64.endian()),
        u32::try_from(dynstr.index().0).expect("fixture dynstr section index")
    );
    assert_eq!(rela_header.sh_type(elf64.endian()), elf::SHT_RELA);
    assert_eq!(
        rela_header.sh_link(elf64.endian()),
        u32::try_from(dynsym.index().0).expect("fixture dynsym section index")
    );
    assert_eq!(rela_header.sh_entsize(elf64.endian()), 24);
    assert_eq!(rela_header.sh_size(elf64.endian()), 48);
    assert!(object.dynamic_symbol_table().is_some());
    assert!(
        object
            .dynamic_symbols()
            .any(|symbol| symbol.name() == Ok("regular_function"))
    );

    let raw_relocations = rela.data().expect("read raw .rela.plt");
    assert_eq!(raw_relocations.len(), 2 * 24);
    let relocation_types = raw_relocations
        .as_chunks::<24>()
        .0
        .iter()
        .map(|entry| u32::from_le_bytes(entry[8..12].try_into().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(
        relocation_types,
        [elf::R_X86_64_JUMP_SLOT, elf::R_X86_64_NONE]
    );
    assert_eq!(
        relocation_types
            .iter()
            .filter(|&&kind| kind == elf::R_X86_64_JUMP_SLOT)
            .count(),
        1
    );

    let plt = object.section_by_name(".plt").expect("PLT section");
    let plt_file_offset = plt.file_range().expect("PLT file range").0;
    assert_ne!(plt_file_offset, plt.address());
    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    // Two raw entries retain the lazy header: one recognized entry alone
    // would equal the 16-byte .plt size and make the old filtered count drop it.
    assert_eq!(
        candidate_at_file_offset(&index, plt_file_offset + 8),
        Some(".plt")
    );
    assert_eq!(
        candidate_at_file_offset(&index, plt_file_offset + 16),
        Some("regular_function@plt")
    );
    let fallback_name = format!("offset_{:#x}@plt", plt_file_offset + 32);
    assert_eq!(
        candidate_at_file_offset(&index, plt_file_offset + 32),
        Some(fallback_name.as_str())
    );
}

#[test]
fn plt_unsupported_relocation_retains_its_linked_symbol_name() {
    use object::{ObjectSymbol as _, ObjectSymbolTable as _};

    let original = elf_with_mixed_plt_relocations();
    let mut builder = build::elf::Builder::read(original.as_slice()).expect("read original ELF");
    let rela = builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".rela.plt")
        .expect("relocation section");
    let build::elf::SectionData::DynamicRelocation(rows) = &mut rela.data else {
        panic!("fixture has structured dynamic relocations");
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].r_type, elf::R_X86_64_NONE);
    assert!(rows[0].symbol.is_some());
    rows[1].symbol = rows[0].symbol;
    let mut bytes = Vec::new();
    builder
        .write(&mut bytes)
        .expect("write named unsupported row");

    let object = object::File::parse(bytes.as_slice()).expect("parse named unsupported row");
    let raw = object
        .section_by_name(".rela.plt")
        .expect("relocation section")
        .data()
        .expect("relocation bytes");
    assert_eq!(raw.len(), 48);
    let entries = raw.as_chunks::<24>().0;
    assert_eq!(
        u32::from_le_bytes(entries[1][8..12].try_into().unwrap()),
        elf::R_X86_64_NONE
    );
    let symbol_index = u32::from_le_bytes(entries[1][12..16].try_into().unwrap());
    assert_ne!(symbol_index, 0);
    assert_eq!(entries[1][12..16], entries[0][12..16]);
    let symbols = object.dynamic_symbol_table().expect("dynamic symbol table");
    assert_eq!(
        symbols
            .symbol_by_index(object::SymbolIndex(
                usize::try_from(symbol_index).expect("fixture symbol index")
            ))
            .expect("linked symbol")
            .name(),
        Ok("regular_function")
    );
    let plt = object.section_by_name(".plt").expect("PLT section");
    assert_eq!(plt.size(), 16);
    let plt_offset = plt.file_range().expect("PLT file range").0;
    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    assert_eq!(
        candidate_at_file_offset(&index, plt_offset + 8),
        Some(".plt")
    );
    assert_eq!(
        candidate_at_file_offset(&index, plt_offset + 16),
        Some("regular_function@plt")
    );
    assert_eq!(
        candidate_at_file_offset(&index, plt_offset + 32),
        Some("regular_function@plt")
    );
}

fn assert_unusable_plt_relocations_retain_header(section_type: u32, clear_link: bool) {
    use object::read::elf::SectionHeader as _;

    let original = elf_with_mixed_plt_relocations();
    let object = object::File::parse(original.as_slice()).expect("parse original ELF");
    let raw_relocations = object
        .section_by_name(".rela.plt")
        .expect("original relocations")
        .data()
        .expect("original relocation bytes")
        .to_vec();
    assert_eq!(raw_relocations.len(), 48);
    let mut builder = build::elf::Builder::read(original.as_slice()).expect("read original ELF");
    let rela = builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".rela.plt")
        .expect("relocation section");
    rela.sh_type = section_type;
    if clear_link {
        rela.sh_link_section = None;
    }
    rela.data = build::elf::SectionData::Data(raw_relocations.clone().into());
    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).expect("write altered ELF");

    let object = object::File::parse(bytes.as_slice()).expect("parse altered ELF");
    let object::File::Elf64(elf64) = &object else {
        panic!("fixture must be ELF64");
    };
    let rela = elf64
        .section_by_name(".rela.plt")
        .expect("altered relocations");
    let header = rela.elf_section_header();
    assert_eq!(header.sh_type(elf64.endian()), section_type);
    let dynsym = elf64.section_by_name(".dynsym").expect("dynamic symbols");
    assert_eq!(
        header.sh_link(elf64.endian()),
        if clear_link {
            0
        } else {
            u32::try_from(dynsym.index().0).expect("fixture dynsym section index")
        }
    );
    assert_eq!(
        rela.data().expect("altered relocation bytes"),
        raw_relocations
    );
    assert!(object.dynamic_symbol_table().is_some());
    let plt = object.section_by_name(".plt").expect("PLT section");
    assert_eq!(plt.size(), 16);
    let plt_offset = plt.file_range().expect("PLT file range").0;

    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    assert_eq!(
        candidate_at_file_offset(&index, plt_offset + 8),
        Some(".plt")
    );
    assert_eq!(candidate_at_file_offset(&index, plt_offset + 16), None);
}

#[test]
fn plt_relocations_with_zero_link_retain_header_without_entries() {
    assert_unusable_plt_relocations_retain_header(elf::SHT_RELA, true);
}

#[test]
fn plt_relocations_with_invalid_section_type_retain_header_without_entries() {
    assert_unusable_plt_relocations_retain_header(elf::SHT_PROGBITS, false);
}

#[test]
fn nobits_plt_without_relocations_retains_header() {
    use object::ObjectSymbol as _;

    let original = elf_with_allocated_plt(
        &[(
            b"regular_function",
            0x1000,
            16,
            elf::STB_GLOBAL,
            elf::STT_FUNC,
        )],
        0x9000,
        16,
    );
    let mut builder = build::elf::Builder::read(original.as_slice()).expect("read PLT ELF");
    let plt = builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".plt")
        .expect("PLT section");
    plt.sh_type = elf::SHT_NOBITS;
    plt.data = build::elf::SectionData::UninitializedData(plt.sh_size);
    builder.set_section_sizes();
    let mut bytes = Vec::new();
    builder.write(&mut bytes).expect("write NOBITS PLT ELF");

    let object = object::File::parse(bytes.as_slice()).expect("parse NOBITS PLT ELF");
    let plt = object.section_by_name(".plt").expect("NOBITS PLT section");
    let (kind, plt_offset) =
        super::super::elf_section_layout(&object, plt.index()).expect("PLT SHDR layout");
    assert_eq!(kind, elf::SHT_NOBITS);
    assert_eq!(plt.size(), 16);
    assert_eq!(plt.file_range(), None);
    assert!(matches!(plt.flags(), object::SectionFlags::Elf { sh_flags }
        if sh_flags & u64::from(elf::SHF_ALLOC) != 0));
    assert!(object.section_by_name(".rela.plt").is_none());
    assert!(object.section_by_name(".rel.plt").is_none());
    assert!(
        object
            .symbols()
            .any(|symbol| symbol.name() == Ok("regular_function"))
    );

    let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
    assert_eq!(candidate_at_file_offset(&index, plt_offset), Some(".plt"));
    assert_eq!(index.symbol_name(0x1008), Some("regular_function"));
}
