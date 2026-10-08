use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use object::{Object, ObjectSection, ObjectSymbol};

const DWO_ID: u64 = 0x1234;
const BASE: u64 = 0x1000;

struct DwarfParts {
    abbrev: Vec<u8>,
    info: Vec<u8>,
    address_offsets: Vec<u64>,
}

fn uleb(bytes: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}

fn abbreviation(
    bytes: &mut Vec<u8>,
    code: u64,
    tag: gimli::DwTag,
    children: bool,
    attributes: &[(gimli::DwAt, gimli::DwForm)],
) {
    uleb(bytes, code);
    uleb(bytes, tag.0.into());
    bytes.push(u8::from(children));
    for (attribute, form) in attributes {
        uleb(bytes, attribute.0.into());
        uleb(bytes, form.0.into());
    }
    bytes.extend_from_slice(&[0, 0]);
}

fn finish_unit(info: &mut [u8]) {
    let length = u32::try_from(info.len() - 4).unwrap();
    info[..4].copy_from_slice(&length.to_le_bytes());
}

fn dwarf_parts(name: &str, base: u64, dwo_id: Option<u64>, supplementary: bool) -> DwarfParts {
    let mut abbrev = Vec::new();
    let mut root_attributes = vec![
        (gimli::DW_AT_low_pc, gimli::DW_FORM_addr),
        (gimli::DW_AT_high_pc, gimli::DW_FORM_data4),
    ];
    if dwo_id.is_some() {
        root_attributes.push((gimli::DW_AT_GNU_dwo_id, gimli::DW_FORM_data8));
    }
    abbreviation(
        &mut abbrev,
        1,
        gimli::DW_TAG_compile_unit,
        true,
        &root_attributes,
    );
    abbreviation(
        &mut abbrev,
        2,
        gimli::DW_TAG_subprogram,
        false,
        &[
            (
                gimli::DW_AT_name,
                if supplementary {
                    gimli::DW_FORM_strp_sup
                } else {
                    gimli::DW_FORM_string
                },
            ),
            (gimli::DW_AT_low_pc, gimli::DW_FORM_addr),
            (gimli::DW_AT_high_pc, gimli::DW_FORM_data4),
        ],
    );
    abbrev.push(0);
    let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1];
    let mut address_offsets = vec![info.len() as u64];
    info.extend_from_slice(&base.to_le_bytes());
    info.extend_from_slice(&16_u32.to_le_bytes());
    if let Some(id) = dwo_id {
        info.extend_from_slice(&id.to_le_bytes());
    }
    info.push(2);
    if supplementary {
        info.extend_from_slice(&0_u32.to_le_bytes());
    } else {
        info.extend_from_slice(name.as_bytes());
        info.push(0);
    }
    address_offsets.push(info.len() as u64);
    info.extend_from_slice(&base.to_le_bytes());
    info.extend_from_slice(&16_u32.to_le_bytes());
    info.push(0);
    finish_unit(&mut info);
    DwarfParts {
        abbrev,
        info,
        address_offsets,
    }
}

fn skeleton() -> DwarfParts {
    let mut abbrev = Vec::new();
    abbreviation(
        &mut abbrev,
        1,
        gimli::DW_TAG_compile_unit,
        false,
        &[
            (gimli::DW_AT_low_pc, gimli::DW_FORM_addr),
            (gimli::DW_AT_high_pc, gimli::DW_FORM_data4),
            (gimli::DW_AT_comp_dir, gimli::DW_FORM_string),
            (gimli::DW_AT_GNU_dwo_name, gimli::DW_FORM_string),
            (gimli::DW_AT_GNU_dwo_id, gimli::DW_FORM_data8),
        ],
    );
    abbrev.push(0);
    let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1];
    info.extend_from_slice(&BASE.to_le_bytes());
    info.extend_from_slice(&16_u32.to_le_bytes());
    info.extend_from_slice(b"snapshot-dir\0unit.dwo\0");
    info.extend_from_slice(&DWO_ID.to_le_bytes());
    finish_unit(&mut info);
    DwarfParts {
        abbrev,
        info,
        address_offsets: Vec::new(),
    }
}

fn elf(sections: &[(&str, &[u8])]) -> Arc<[u8]> {
    let mut object = object::write::Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::X86_64,
        object::Endianness::Little,
    );
    for (name, data) in sections {
        let section = object.add_section(
            Vec::new(),
            name.as_bytes().to_vec(),
            object::SectionKind::Debug,
        );
        object.append_section_data(section, data, 1);
    }
    object.write().unwrap().into()
}

fn dwarf_elf(parts: &DwarfParts, split: bool) -> Arc<[u8]> {
    elf(&[
        (
            if split {
                ".debug_abbrev.dwo"
            } else {
                ".debug_abbrev"
            },
            &parts.abbrev,
        ),
        (
            if split {
                ".debug_info.dwo"
            } else {
                ".debug_info"
            },
            &parts.info,
        ),
    ])
}

fn package(parts: &DwarfParts, id: u64) -> Arc<[u8]> {
    // GNU DWARF4 package index: two sections, one CU, two hash slots.
    let mut index = Vec::new();
    for value in [2_u32, 2, 1, 2] {
        index.extend_from_slice(&value.to_le_bytes());
    }
    for value in [id, 0] {
        index.extend_from_slice(&value.to_le_bytes());
    }
    for value in [
        1_u32,
        0,
        1,
        3,
        0,
        0,
        u32::try_from(parts.info.len()).unwrap(),
        u32::try_from(parts.abbrev.len()).unwrap(),
    ] {
        index.extend_from_slice(&value.to_le_bytes());
    }
    elf(&[
        (".debug_cu_index", &index),
        (".debug_abbrev.dwo", &parts.abbrev),
        (".debug_info.dwo", &parts.info),
    ])
}

type OpenedPaths = Arc<Mutex<Vec<PathBuf>>>;

fn loader(
    main: &Path,
    supplementary: Option<&Path>,
    files: Vec<(PathBuf, Arc<[u8]>)>,
) -> (addr2line::Loader, OpenedPaths) {
    let files = files.into_iter().collect::<BTreeMap<_, _>>();
    let opened = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&opened);
    let loader = addr2line::Loader::new_with_sup_and_opener(main, supplementary, move |path| {
        recorded.lock().unwrap().push(path.to_path_buf());
        files.get(path).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "fixture callback miss").into()
        })
    })
    .unwrap();
    (loader, opened)
}

fn frame_names(loader: &addr2line::Loader, probe: u64) -> Vec<String> {
    let mut frames = loader.find_frames(probe).unwrap();
    let mut names = Vec::new();
    while let Some(frame) = frames.next().unwrap() {
        if let Some(function) = frame.function {
            names.push(function.raw_name().unwrap().into_owned());
        }
    }
    names
}

#[test]
fn pyroc48_loader_retains_main_arc_and_supplementary_names() {
    let parts = dwarf_parts("unused", BASE, None, true);
    let main = dwarf_elf(&parts, false);
    let sup = elf(&[(".debug_str", b"supplementary_name\0")]);
    let main_path = Path::new("snapshot-main.so");
    let sup_path = Path::new("snapshot-main.sup");
    let (loader, opened) = loader(
        main_path,
        Some(sup_path),
        vec![
            (main_path.into(), Arc::clone(&main)),
            (sup_path.into(), sup),
        ],
    );
    // Caller, retained callback table, and arena share exactly this allocation.
    assert_eq!(Arc::strong_count(&main), 3);
    assert_eq!(frame_names(&loader, BASE + 1), ["supplementary_name"]);
    assert_eq!(
        *opened.lock().unwrap(),
        [main_path, sup_path, Path::new("snapshot-main.so.dwp")]
    );
    drop(loader);
    assert_eq!(Arc::strong_count(&main), 1);
}

#[test]
fn pyroc48_loader_retains_opener_for_lazy_dwo_and_checks_id() {
    for (id, expected) in [
        (DWO_ID, vec!["dwo_name".to_owned()]),
        (DWO_ID + 1, Vec::new()),
    ] {
        let main_path = Path::new("snapshot-main.so");
        let dwo_path = Path::new("snapshot-dir/unit.dwo");
        let (loader, opened) = loader(
            main_path,
            None,
            vec![
                (main_path.into(), dwarf_elf(&skeleton(), false)),
                (
                    dwo_path.into(),
                    dwarf_elf(&dwarf_parts("dwo_name", BASE, Some(id), false), true),
                ),
            ],
        );
        assert_eq!(
            *opened.lock().unwrap(),
            [main_path, Path::new("snapshot-main.so.dwp")]
        );
        assert_eq!(frame_names(&loader, BASE + 1), expected);
        assert_eq!(opened.lock().unwrap().last().unwrap(), dwo_path);
        let count = opened.lock().unwrap().len();
        assert_eq!(frame_names(&loader, BASE + 2), expected);
        assert_eq!(opened.lock().unwrap().len(), count, "DWO result is cached");
    }
}

#[test]
fn pyroc48_loader_dwp_precedes_valid_dwo() {
    let main_path = Path::new("snapshot-main.so");
    let dwp_path = Path::new("snapshot-main.so.dwp");
    let dwo_path = Path::new("snapshot-dir/unit.dwo");
    for (id, expected) in [(DWO_ID, "package_name"), (DWO_ID + 1, "dwo_name")] {
        let (loader, opened) = loader(
            main_path,
            None,
            vec![
                (main_path.into(), dwarf_elf(&skeleton(), false)),
                (
                    dwp_path.into(),
                    package(&dwarf_parts("package_name", BASE, Some(id), false), id),
                ),
                (
                    dwo_path.into(),
                    dwarf_elf(&dwarf_parts("dwo_name", BASE, Some(DWO_ID), false), true),
                ),
            ],
        );
        assert_eq!(frame_names(&loader, BASE + 1), [expected]);
        if id == DWO_ID {
            assert_eq!(*opened.lock().unwrap(), [main_path, dwp_path]);
        } else {
            assert_eq!(*opened.lock().unwrap(), [main_path, dwp_path, dwo_path]);
        }
    }
}

#[test]
fn pyroc48_loader_required_callback_errors_propagate() {
    let error = || std::io::Error::new(std::io::ErrorKind::PermissionDenied, "opener rejected");
    assert!(addr2line::Loader::new_with_opener("main", move |_| Err(error().into())).is_err());
    let bytes = elf(&[]);
    assert!(
        addr2line::Loader::new_with_sup_and_opener("main", Some("sup"), move |path| {
            if path == Path::new("main") {
                Ok(Arc::clone(&bytes))
            } else {
                Err(error().into())
            }
        })
        .is_err()
    );
}

fn word(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn quad(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn fixed_name(bytes: &mut Vec<u8>, name: &str) {
    assert!(name.len() <= 16);
    bytes.extend_from_slice(name.as_bytes());
    bytes.resize(bytes.len() + 16 - name.len(), 0);
}

fn macho(uuid: [u8; 16], sections: &[(&str, &[u8])], symbols: &[(&str, u8, u64)]) -> Arc<[u8]> {
    // Raw commands permit UUID and ordered STABS, which object::write does not
    // currently expose. All offsets are computed before emitting the payload.
    let segment_size = if sections.is_empty() {
        0
    } else {
        72 + 80 * sections.len()
    };
    let command_size = segment_size + 24 + 24;
    let data_offset = 32 + command_size;
    let data_size = sections.iter().map(|(_, data)| data.len()).sum::<usize>();
    let sym_offset = data_offset + data_size;
    let str_offset = sym_offset + 16 * symbols.len();
    let mut strings = vec![0];
    let mut string_offsets = Vec::new();
    for (name, _, _) in symbols {
        string_offsets.push(u32::try_from(strings.len()).unwrap());
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    let mut bytes = Vec::new();
    for value in [
        object::macho::MH_MAGIC_64,
        object::macho::CPU_TYPE_X86_64,
        3,
        object::macho::MH_OBJECT,
        2 + u32::from(!sections.is_empty()),
        u32::try_from(command_size).unwrap(),
        0,
        0,
    ] {
        word(&mut bytes, value);
    }
    if !sections.is_empty() {
        word(&mut bytes, object::macho::LC_SEGMENT_64);
        word(&mut bytes, u32::try_from(segment_size).unwrap());
        fixed_name(&mut bytes, "__DWARF");
        quad(&mut bytes, 0);
        quad(&mut bytes, data_size as u64);
        quad(&mut bytes, data_offset as u64);
        quad(&mut bytes, data_size as u64);
        for value in [7, 7, u32::try_from(sections.len()).unwrap(), 0] {
            word(&mut bytes, value);
        }
        let mut offset = data_offset;
        for (name, data) in sections {
            fixed_name(&mut bytes, name);
            fixed_name(&mut bytes, "__DWARF");
            quad(&mut bytes, (offset - data_offset) as u64);
            quad(&mut bytes, data.len() as u64);
            for value in [
                u32::try_from(offset).unwrap(),
                0,
                0,
                0,
                object::macho::S_ATTR_DEBUG,
                0,
                0,
                0,
            ] {
                word(&mut bytes, value);
            }
            offset += data.len();
        }
    }
    word(&mut bytes, object::macho::LC_UUID);
    word(&mut bytes, 24);
    bytes.extend_from_slice(&uuid);
    for value in [
        object::macho::LC_SYMTAB,
        24,
        u32::try_from(sym_offset).unwrap(),
        u32::try_from(symbols.len()).unwrap(),
        u32::try_from(str_offset).unwrap(),
        u32::try_from(strings.len()).unwrap(),
    ] {
        word(&mut bytes, value);
    }
    assert_eq!(bytes.len(), data_offset);
    for (_, data) in sections {
        bytes.extend_from_slice(data);
    }
    for ((_, kind, value), string_offset) in symbols.iter().zip(string_offsets) {
        word(&mut bytes, string_offset);
        bytes.extend_from_slice(&[*kind, 0, 0, 0]);
        quad(&mut bytes, *value);
    }
    bytes.extend_from_slice(&strings);
    assert_eq!(
        object::File::parse(bytes.as_slice())
            .unwrap()
            .mach_uuid()
            .unwrap(),
        Some(uuid)
    );
    bytes.into()
}

#[test]
fn pyroc48_loader_dsym_callback_requires_matching_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("main.macho");
    let dwarf_dir = dir.path().join("main.dSYM/Contents/Resources/DWARF");
    std::fs::create_dir_all(&dwarf_dir).unwrap();
    let wrong_path = dwarf_dir.join("wrong");
    let right_path = dwarf_dir.join("right");
    // Files provide directory entries only: callback bytes must be used.
    std::fs::write(&wrong_path, b"not an object").unwrap();
    let wrong = dwarf_parts("wrong_uuid", BASE, None, false);
    let right = dwarf_parts("matching_uuid", BASE, None, false);
    let main = macho([7; 16], &[], &[]);
    let wrong = macho(
        [8; 16],
        &[
            ("__debug_abbrev", &wrong.abbrev),
            ("__debug_info", &wrong.info),
        ],
        &[],
    );
    let right = macho(
        [7; 16],
        &[
            ("__debug_abbrev", &right.abbrev),
            ("__debug_info", &right.info),
        ],
        &[],
    );
    {
        let (loader, opened) = loader(
            &main_path,
            None,
            vec![
                (main_path.clone(), Arc::clone(&main)),
                (wrong_path.clone(), Arc::clone(&wrong)),
            ],
        );
        assert!(frame_names(&loader, BASE + 1).is_empty());
        assert!(opened.lock().unwrap().contains(&wrong_path));
    }
    std::fs::write(&right_path, b"not an object either").unwrap();
    let (loader, opened) = loader(
        &main_path,
        None,
        vec![
            (main_path.clone(), main),
            (wrong_path, wrong),
            (right_path.clone(), right),
        ],
    );
    assert_eq!(frame_names(&loader, BASE + 1), ["matching_uuid"]);
    assert!(opened.lock().unwrap().contains(&right_path));
}

fn relocated_macho_member(name: &str) -> Arc<[u8]> {
    let parts = dwarf_parts(name, 0, None, false);
    let mut object = object::write::Object::new(
        object::BinaryFormat::MachO,
        object::Architecture::X86_64,
        object::Endianness::Little,
    );
    let text = object.section_id(object::write::StandardSection::Text);
    object.append_section_data(text, &[0x90; 64], 1);
    let symbol = object.add_symbol(object::write::Symbol {
        name: b"linked".to_vec(),
        value: 0x20,
        size: 16,
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: object::write::SymbolSection::Section(text),
        flags: object::SymbolFlags::None,
    });
    let abbrev = object.add_section(
        b"__DWARF".to_vec(),
        b"__debug_abbrev".to_vec(),
        object::SectionKind::Debug,
    );
    object.append_section_data(abbrev, &parts.abbrev, 1);
    let info = object.add_section(
        b"__DWARF".to_vec(),
        b"__debug_info".to_vec(),
        object::SectionKind::Debug,
    );
    object.append_section_data(info, &parts.info, 1);
    for offset in parts.address_offsets {
        object
            .add_relocation(
                info,
                object::write::Relocation {
                    offset,
                    symbol,
                    addend: 0,
                    flags: object::RelocationFlags::Generic {
                        kind: object::RelocationKind::Absolute,
                        encoding: object::RelocationEncoding::Generic,
                        size: 64,
                    },
                },
            )
            .unwrap();
    }
    let bytes = object.write().unwrap();
    let parsed = object::File::parse(bytes.as_slice()).unwrap();
    assert_eq!(parsed.format(), object::BinaryFormat::MachO);
    assert_eq!(
        parsed
            .section_by_name(".debug_info")
            .unwrap()
            .relocations()
            .count(),
        2
    );
    let linked = parsed
        .symbols()
        .find(|symbol| symbol.name().unwrap() == "_linked")
        .unwrap();
    assert_eq!(linked.address(), 0x20);
    bytes.into()
}

fn archive(members: &[(&str, Arc<[u8]>)]) -> Arc<[u8]> {
    let mut bytes = b"!<arch>\n".to_vec();
    for (name, data) in members {
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            format!("{name}/"),
            0,
            0,
            0,
            "100644",
            data.len()
        );
        assert_eq!(header.len(), 60);
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(data);
        if data.len() % 2 != 0 {
            bytes.push(b'\n');
        }
    }
    let parsed = object::read::archive::ArchiveFile::parse(bytes.as_slice()).unwrap();
    assert_eq!(parsed.members().count(), members.len());
    bytes.into()
}

#[test]
fn pyroc48_loader_lazy_macho_object_and_archive_member_relocations() {
    for archived in [false, true] {
        let main_path = Path::new("snapshot-main.macho");
        let object_path = Path::new(if archived {
            "snapshot-objects.a"
        } else {
            "snapshot-object.o"
        });
        let oso = if archived {
            "snapshot-objects.a(object.o)"
        } else {
            "snapshot-object.o"
        };
        let main = macho(
            [7; 16],
            &[],
            &[
                (oso, object::macho::N_OSO, 0),
                ("_linked", object::macho::N_FUN, BASE),
                ("", object::macho::N_FUN, 16),
            ],
        );
        let parsed = object::File::parse(main.as_ref()).unwrap();
        let map = parsed.object_map();
        assert_eq!(
            map.get(BASE + 1).unwrap().object(&map).member().is_some(),
            archived
        );
        let member = relocated_macho_member("relocated_member");
        let data = if archived {
            archive(&[
                ("other.o", relocated_macho_member("wrong_member")),
                ("object.o", member),
            ])
        } else {
            member
        };
        let (loader, opened) = loader(
            main_path,
            None,
            vec![(main_path.into(), main), (object_path.into(), data)],
        );
        assert!(!opened.lock().unwrap().contains(&object_path.to_path_buf()));
        assert_eq!(frame_names(&loader, BASE + 1), ["relocated_member"]);
        assert_eq!(opened.lock().unwrap().last().unwrap(), object_path);
        let count = opened.lock().unwrap().len();
        assert_eq!(frame_names(&loader, BASE + 2), ["relocated_member"]);
        assert_eq!(
            opened.lock().unwrap().len(),
            count,
            "Mach-O context is cached"
        );
    }
}

#[test]
fn pyroc48_loader_default_constructor_still_loads_regular_dwarf() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.so");
    std::fs::write(
        &path,
        dwarf_elf(&dwarf_parts("default_name", BASE, None, false), false),
    )
    .unwrap();
    let loader = addr2line::Loader::new(&path).unwrap();
    assert_eq!(frame_names(&loader, BASE + 1), ["default_name"]);
}
