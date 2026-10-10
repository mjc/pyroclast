use super::*;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn section_type(bytes: &[u8], name: &str) -> u32 {
    use object::Object as _;
    use object::read::elf::SectionHeader as _;

    let object::File::Elf64(elf) = object::File::parse(bytes).unwrap() else {
        panic!("fixture must be ELF64");
    };
    elf.section_by_name(name)
        .unwrap()
        .elf_section_header()
        .sh_type(elf.endian())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn section_offset(bytes: &[u8], name: &str) -> u64 {
    use object::Object as _;
    use object::read::elf::SectionHeader as _;

    let object::File::Elf64(elf) = object::File::parse(bytes).unwrap() else {
        panic!("fixture must be ELF64");
    };
    elf.section_by_name(name)
        .unwrap()
        .elf_section_header()
        .sh_offset(elf.endian())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_contiguous_sibling_section_lookup_matches_perf() {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
    use std::fmt::Write as _;

    const MAP: u64 = 0xffff_ffff_c100_0000;
    const SAMPLE: u64 = MAP + 0x25;
    let (root, bytes) = write_native_module_object_queries(
        true,
        false,
        &[(SAMPLE, &[SAMPLE]), (SAMPLE, &[SAMPLE])],
        true,
    );
    let module = root.path().join("a.ko");
    let original = std::fs::read(&module).unwrap();
    let id = object::File::parse(original.as_slice())
        .unwrap()
        .build_id()
        .unwrap()
        .unwrap()
        .to_vec();
    let hex = id.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    });
    let assembly = root.path().join("sibling.S");
    std::fs::write(
        &assembly,
        ".section .text,\"ax\",@progbits\n.globl cached_module_object\n.type cached_module_object,@function\ncached_module_object:\n.fill 32,1,0x90\n.size cached_module_object,.-cached_module_object\n.section .noinstr.text,\"ax\",@progbits\n.globl extra_function\n.type extra_function,@function\nextra_function:\n.fill 32,1,0x90\n.size extra_function,.-extra_function\n",
    )
    .unwrap();
    let output = Command::new("cc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-e,cached_module_object",
            "-Wl,-z,max-page-size=0x1000",
            "-Wl,-Ttext=0xffffffffc1000000",
            "-Wl,--section-start=.noinstr.text=0xffffffffc1000020",
        ])
        .arg(format!("-Wl,--build-id=0x{hex}"))
        .arg("-o")
        .arg(&module)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let image = std::fs::read(&module).unwrap();
    let elf = object::File::parse(image.as_slice()).unwrap();
    let text = elf.section_by_name(".text").unwrap();
    let sibling = elf.section_by_name(".noinstr.text").unwrap();
    assert_eq!(elf.build_id().unwrap().unwrap(), id);
    let text_offset = text.file_range().unwrap().0;
    let sibling_offset = sibling.file_range().unwrap().0;
    assert_eq!((text.address(), text.size()), (MAP, 0x20));
    assert_eq!((sibling.address(), sibling.size()), (MAP + 0x20, 0x20));
    assert!(
        matches!(text.flags(), object::SectionFlags::Elf { sh_flags } if sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0)
    );
    assert!(
        matches!(sibling.flags(), object::SectionFlags::Elf { sh_flags } if sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0)
    );
    assert_eq!(sibling_offset, text_offset + text.size());
    assert!(elf.symbols().any(|symbol| {
        symbol.name() == Ok("cached_module_object")
            && symbol.address() == MAP
            && symbol.size() == 0x20
    }));
    assert!(
        elf.symbols().any(|symbol| {
            symbol.name() == Ok("extra_function") && symbol.address() == MAP + 0x20
        })
    );

    let (perf_script, stderr, native) = query_native_module_object(root.path());
    assert!(perf_script.contains("extra_function+0x5"), "{perf_script}");
    assert_eq!(
        perf_script.matches("extra_function+0x5").count(),
        2,
        "{perf_script}"
    );
    assert!(perf_script.contains("extra_function+0x5"), "{perf_script}");
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert_module_symbol_routes_match_native(root.path(), &bytes, &perf_script, &native);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn assert_split_debug_module_geometry(
    runtime: &[u8],
    debug: &[u8],
    id: &[u8],
    map: u64,
    sample: u64,
    objcopy_text_offset: u64,
) {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

    let runtime_elf = object::File::parse(runtime).unwrap();
    let runtime_text = runtime_elf.section_by_name(".text").unwrap();
    assert_eq!(runtime_elf.build_id().unwrap().unwrap(), id);
    assert_eq!(section_type(runtime, ".dynsym"), object::elf::SHT_DYNSYM);
    assert_eq!(runtime_text.address(), map);
    assert_eq!(runtime_text.size(), 0x2000);
    assert_eq!(runtime_text.file_range().unwrap().0, 0x1000);
    assert!(runtime_elf.symbols().any(|symbol| {
        symbol.name() == Ok("cached_module_object")
            && symbol.address() == map
            && symbol.size() == 0x20
    }));
    let tail = runtime_elf
        .symbols()
        .find(|symbol| symbol.name() == Ok("tail_function"))
        .unwrap();
    assert_eq!(tail.address(), map + 0x400);
    assert_eq!(tail.size(), 0);
    assert!(tail.is_global());
    let debug_elf = object::File::parse(debug).unwrap();
    let debug_text = debug_elf.section_by_name(".text").unwrap();
    assert_eq!(debug_elf.build_id().unwrap().unwrap(), id);
    assert_eq!(section_type(debug, ".dynsym"), object::elf::SHT_NOBITS);
    assert_eq!(debug_text.index(), runtime_text.index());
    assert_eq!(debug_text.address(), runtime_text.address());
    assert_eq!(debug_text.size(), runtime_text.size());
    let runtime_text_offset = section_offset(runtime, ".text");
    let debug_text_offset = section_offset(debug, ".text");
    assert_eq!(runtime_text_offset, 0x1000);
    assert!(
        debug_text_offset + (tail.address() - map) < runtime_text_offset,
        "debug offset={debug_text_offset:#x}, objcopy offset={objcopy_text_offset:#x}, runtime offset={runtime_text_offset:#x}, tail delta={:#x}",
        tail.address() - map
    );
    assert!(debug_text_offset + (sample - map) > runtime_text.size());
    assert_eq!(debug_text_offset, 0x40);
    let debug_tail = debug_elf
        .symbols()
        .find(|symbol| symbol.name() == Ok("tail_function"))
        .unwrap();
    assert_eq!(debug_tail.section_index(), tail.section_index());
    assert_eq!(debug_tail.address(), tail.address());
    assert_eq!(debug_tail.size(), 0);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_split_debug_zero_size_tail_lookup_matches_perf() {
    use object::Object as _;
    use std::fmt::Write as _;

    const MAP: u64 = 0xffff_ffff_c100_0000;
    const SAMPLE: u64 = MAP + 0x1fe0;
    let (root, bytes) = write_native_module_object_queries(
        true,
        false,
        &[(SAMPLE, &[SAMPLE]), (SAMPLE, &[SAMPLE])],
        true,
    );
    let module = root.path().join("a.ko");
    let original = std::fs::read(&module).unwrap();
    let id = object::File::parse(original.as_slice())
        .unwrap()
        .build_id()
        .unwrap()
        .unwrap()
        .to_vec();
    let hex = id.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    });
    let assembly = root.path().join("tail.S");
    std::fs::write(
        &assembly,
        ".section .text,\"ax\",@progbits\n.globl cached_module_object\n.type cached_module_object,@function\ncached_module_object:\n.fill 32,1,0x90\n.size cached_module_object,.-cached_module_object\n.fill 0x3e0,1,0x90\n.globl tail_function\n.type tail_function,@function\ntail_function:\n.fill 1,1,0x90\n.fill 0x1bff,1,0x90\n",
    )
    .unwrap();
    let output = Command::new("cc")
        .args([
            "-nostdlib",
            "-shared",
            "-Wl,-e,cached_module_object",
            "-Wl,-z,max-page-size=0x1000",
            "-Wl,-Ttext=0xffffffffc1000000",
        ])
        .arg(format!("-Wl,--build-id=0x{hex}"))
        .arg("-o")
        .arg(&module)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let runtime = std::fs::read(&module).unwrap();

    let cache = pyroclast::symbols::perf_build_id_elf_path(&root.path().join(".debug"), &hex);
    let copy = Command::new("objcopy")
        .arg("--only-keep-debug")
        .arg(&module)
        .arg(&cache)
        .output()
        .unwrap();
    assert!(
        copy.status.success(),
        "{}",
        String::from_utf8_lossy(&copy.stderr)
    );
    let objcopy_debug = std::fs::read(&cache).unwrap();
    let objcopy_text_offset = section_offset(&objcopy_debug, ".text");
    let mut debug_builder = object::build::elf::Builder::read(objcopy_debug.as_slice())
        .expect("read objcopy debug ELF");
    let debug_text_section = debug_builder
        .sections
        .iter_mut()
        .find(|section| section.name.as_slice() == b".text")
        .expect("debug text section");
    assert_eq!(debug_text_section.sh_type, object::elf::SHT_NOBITS);
    assert_eq!(
        debug_text_section.sh_flags
            & u64::from(object::elf::SHF_ALLOC | object::elf::SHF_EXECINSTR),
        u64::from(object::elf::SHF_ALLOC | object::elf::SHF_EXECINSTR)
    );
    // Model split-debug source geometry explicitly: NOBITS has no file bytes,
    // so moving only sh_offset preserves its index, type, VMA, and build ID.
    debug_text_section.sh_offset = 0x40;
    let mut debug = Vec::new();
    debug_builder
        .write(&mut debug)
        .expect("write split-debug source geometry");
    std::fs::write(&cache, &debug).unwrap();
    assert_split_debug_module_geometry(&runtime, &debug, &id, MAP, SAMPLE, objcopy_text_offset);

    let (perf_script, stderr, native) = query_native_module_object(root.path());
    assert!(
        perf_script.contains("tail_function+0x1be0"),
        "{perf_script}"
    );
    assert_eq!(
        perf_script.matches("tail_function+0x1be0").count(),
        2,
        "{perf_script}"
    );
    assert!(
        perf_script.contains("tail_function+0x1be0"),
        "{perf_script}"
    );
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert_module_symbol_routes_match_native(root.path(), &bytes, &perf_script, &native);
}
