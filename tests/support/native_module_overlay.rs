use super::native_label_eligibility::label_recording;
use super::*;

const LABEL_ADDRESS: u64 = 0xffff_ffff_c100_8010;
const LABEL_SAMPLE: u64 = LABEL_ADDRESS + 5;

fn rewrite_label_section(path: &std::path::Path, runtime: bool, eligible: bool) {
    let original = std::fs::read(path).unwrap();
    let mut builder = object::build::elf::Builder::read(original.as_slice()).unwrap();
    let section = builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".noinstr.text")
        .unwrap();
    let section_id = section.id();
    if !eligible {
        section.name = b".cold".as_slice().into();
    }
    let guard = builder
        .symbols
        .iter_mut()
        .find(|symbol| symbol.name.as_slice() == b"separate_module_text")
        .unwrap();
    guard.name = if runtime {
        b"runtime_only_guard".as_slice()
    } else {
        b"selected_debug_guard".as_slice()
    }
    .into();
    guard.st_size = 0x10;
    guard.st_value = LABEL_ADDRESS - 0x10;
    let label = builder.symbols.add();
    label.name = if runtime {
        b"runtime_only_label".as_slice()
    } else {
        b"selected_debug_label".as_slice()
    }
    .into();
    label.st_value = LABEL_ADDRESS;
    label.st_size = 0x10;
    label.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_NOTYPE);
    label.section = Some(section_id);
    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn assert_label_source_pair(runtime: &[u8], debug: &[u8], runtime_eligible: bool) {
    use object::{ObjectSection as _, read::elf::SectionHeader as _};
    let runtime_elf = object::File::parse(runtime).unwrap();
    let debug_elf = object::File::parse(debug).unwrap();
    assert!(runtime_elf.build_id().unwrap().is_some());
    assert_eq!(
        runtime_elf.build_id().unwrap(),
        debug_elf.build_id().unwrap()
    );
    let mut indexes = Vec::new();
    for (bytes, name, eligible, kind) in [
        (
            runtime,
            "runtime_only_label",
            runtime_eligible,
            object::elf::SHT_PROGBITS,
        ),
        (
            debug,
            "selected_debug_label",
            !runtime_eligible,
            object::elf::SHT_NOBITS,
        ),
    ] {
        let object::File::Elf64(elf) = object::File::parse(bytes).unwrap() else {
            panic!("fixture must be ELF64");
        };
        let label = elf
            .symbols()
            .find(|symbol| symbol.name() == Ok(name))
            .unwrap();
        assert_eq!(label.address(), LABEL_ADDRESS);
        assert_eq!(label.size(), 0x10);
        assert!(
            matches!(label.flags(), object::SymbolFlags::Elf { st_info, .. }
            if st_info & 0xf == object::elf::STT_NOTYPE)
        );
        let section = elf
            .section_by_index(label.section_index().unwrap())
            .unwrap();
        let header = section.elf_section_header();
        assert_eq!(header.sh_type(elf.endian()), kind);
        assert_ne!(
            header.sh_flags(elf.endian()) & u64::from(object::elf::SHF_ALLOC),
            0
        );
        assert_eq!(
            section.name().unwrap(),
            if eligible { ".noinstr.text" } else { ".cold" }
        );
        assert!(
            section.address() <= LABEL_SAMPLE && LABEL_SAMPLE < section.address() + section.size()
        );
        indexes.push(section.index());
        let guard_name = if name == "runtime_only_label" {
            "runtime_only_guard"
        } else {
            "selected_debug_guard"
        };
        assert!(elf.symbols().any(|symbol| symbol.name() == Ok(guard_name)
            && symbol.address() == LABEL_ADDRESS - 0x10
            && symbol.size() == 0x10));
    }
    assert_eq!(indexes[0], indexes[1]);
}

fn assert_native_label_after_runtime_substitution(runtime_eligible: bool) {
    let (root, original_recording, cache) = write_native_split_debug_module_fixture();
    let module = root.path().join("a.ko");
    rewrite_label_section(&module, true, runtime_eligible);
    rewrite_label_section(&cache, false, !runtime_eligible);
    let runtime = std::fs::read(&module).unwrap();
    let debug = std::fs::read(&cache).unwrap();
    assert_label_source_pair(&runtime, &debug, runtime_eligible);
    let bytes = label_recording(&original_recording, LABEL_SAMPLE);
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    let (script, stderr, native) = query_native_module_object(root.path());
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert!(
        stderr.contains("symbol__new: selected_debug_guard "),
        "native must select debug ELF: {stderr}"
    );
    assert!(
        !stderr.contains("symbol__new: runtime_only_guard "),
        "{stderr}"
    );
    assert!(script.contains(&format!("{LABEL_SAMPLE:x}")), "{script}");
    assert!(
        !script.contains("runtime_only_label"),
        "native must use debug names: {script}"
    );
    if runtime_eligible {
        assert_eq!(
            script.matches("selected_debug_label+0x5").count(),
            1,
            "{script}"
        );
    } else {
        assert!(!script.contains("selected_debug_label"), "{script}");
        assert!(script.contains(&format!("{LABEL_SAMPLE:x}")), "{script}");
    }
    assert_module_symbol_routes_match_native(root.path(), &bytes, &script, &native);
}

#[test]
fn native_split_debug_label_accepts_runtime_section_name_before_lookup() {
    assert_native_label_after_runtime_substitution(true);
}

#[test]
fn native_split_debug_label_rejects_runtime_section_name_before_lookup() {
    assert_native_label_after_runtime_substitution(false);
}

#[path = "native_module_delivery.rs"]
mod delivery;
