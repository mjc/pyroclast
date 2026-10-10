use super::*;
use pyroclast::perfdata::mappings::{MmapTable, ResolvedMappingRef};
use pyroclast::symbols::{KernelModuleObjectMetadata, RustAddr2lineResolver};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

#[path = "native_module_kcore_retirement.rs"]
mod kcore_retirement;

struct DeliveredRequests<R> {
    inner: R,
    requests: Rc<RefCell<Vec<SymbolRequest>>>,
}

impl<R: SymbolResolver> SymbolResolver for DeliveredRequests<R> {
    fn initialize_kernel_maps(&self, table: &MmapTable) {
        self.inner.initialize_kernel_maps(table);
    }

    fn object_build_id(&self, path: &Path) -> Option<Vec<u8>> {
        self.inner.object_build_id(path)
    }

    fn selected_object_module_metadata(
        &self,
        path: &Path,
        module: &SymbolRequest,
    ) -> Option<Arc<KernelModuleObjectMetadata>> {
        self.inner.selected_object_module_metadata(path, module)
    }

    fn requires_kernel_cursor_order(&self) -> bool {
        self.inner.requires_kernel_cursor_order()
    }

    fn preprocess_sample_ip(&self, mapping: &ResolvedMappingRef<'_>) {
        self.inner.preprocess_sample_ip(mapping);
    }
    fn loaded_kernel_module(
        &self,
        mapping: &ResolvedMappingRef<'_>,
    ) -> Option<pyroclast::symbols::LoadedKernelModule> {
        self.inner.loaded_kernel_module(mapping)
    }

    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.requests.borrow_mut().extend_from_slice(requests);
        self.inner.resolve_batch(requests)
    }

    fn resolve_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        self.requests.borrow_mut().extend_from_slice(requests);
        self.inner.resolve_frame_batch_with_metadata(requests)
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        self.requests.borrow_mut().extend_from_slice(requests);
        self.inner.resolve_base_frame_batch_with_metadata(requests)
    }

    fn resolve_original_kernel_module_frames(
        &self,
        request: &SymbolRequest,
        inline: bool,
    ) -> Result<ResolvedSymbolFrames, String> {
        self.inner
            .resolve_original_kernel_module_frames(request, inline)
    }
}

#[test]
fn loaded_module_section_is_delivered_to_the_symbol_resolver() {
    let (root, original, cache) = write_native_split_debug_module_fixture();
    let module = root.path().join("a.ko");
    rewrite_label_section(&module, true, true);
    rewrite_label_section(&cache, false, false);
    assert_label_source_pair(
        &std::fs::read(&module).unwrap(),
        &std::fs::read(&cache).unwrap(),
        true,
    );
    let bytes = label_recording(&original, LABEL_SAMPLE);
    let input = root.path().join("perf.data");
    std::fs::write(&input, &bytes).unwrap();
    let (script, stderr, _) = query_native_module_object(root.path());
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert!(
        script.contains("selected_debug_label+0x5 ([a].noinstr.text)"),
        "{script}"
    );
    let resolver = DeliveredRequests {
        inner: perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            RustAddr2lineResolver::new(),
            &input,
            root.path(),
            [],
            &root.path().join("kallsyms"),
        ),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver).unwrap();
    let requests = resolver.requests.borrow();
    assert!(
        requests
            .iter()
            .any(|request| { request.kernel_module_address == Some(0xffff_ffff_c100_0010) }),
        "recorded main module must have loaded: {requests:?}"
    );
    let delivered = requests
        .iter()
        .find(|request| request.kernel_module_address == Some(LABEL_SAMPLE));
    assert!(
        delivered.is_some(),
        "loaded extra section never reached symbol lookup: {requests:?}"
    );
    let delivered = delivered.unwrap();
    assert_eq!(
        delivered.kernel_mapping_range,
        Some((0xffff_ffff_c100_8000, 0xffff_ffff_c100_8200))
    );
}

#[test]
fn generated_child_uses_selected_base_arena_and_runtime_long_name_for_inlines() {
    let (root, original, source) = write_native_split_debug_module_fixture();
    let module = root.path().join("a.ko");
    rewrite_label_section(&module, true, true);
    rewrite_label_section(&source, false, false);
    assert_label_source_pair(
        &std::fs::read(&module).unwrap(),
        &std::fs::read(&source).unwrap(),
        true,
    );
    let bytes = label_recording(&original, LABEL_SAMPLE);
    let input = root.path().join("perf.data");
    std::fs::write(&input, &bytes).unwrap();
    let (script, stderr, native) = query_native_module_object(root.path());
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert!(
        script.contains("selected_debug_label+0x5 ([a].noinstr.text)"),
        "{script}"
    );
    let requests = Rc::new(RefCell::new(Vec::new()));
    let objects = DeliveredRequests {
        inner: RustAddr2lineResolver::new(),
        requests: Rc::clone(&requests),
    };
    let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
        objects,
        &input,
        root.path(),
        [],
        &root.path().join("kallsyms"),
    );
    assert_eq!(
        fold_perfdata_callchains_with_symbols(
            &bytes,
            FoldOptions {
                inline: true,
                ..FoldOptions::default()
            },
            &resolver
        )
        .unwrap()
        .as_bytes(),
        native.as_slice()
    );
    let requests = requests.borrow();
    assert!(
        requests.iter().any(|request| request.path == source
            && matches!(
                request.symbol_lookup,
                pyroclast::symbols::SymbolLookup::KernelModuleSection { .. }
            )),
        "selected arena must supply child base metadata: {requests:?}"
    );
    assert!(
        requests.iter().any(
            |request| request.path == module && request.addr2line_address == Some(LABEL_SAMPLE)
        ),
        "native child inherits runtime long_name for inline lookup: {requests:?}"
    );
}

fn delivered_requests(root: &Path, bytes: &[u8]) -> Vec<SymbolRequest> {
    let resolver = DeliveredRequests {
        inner: perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            RustAddr2lineResolver::new(),
            &root.join("perf.data"),
            root,
            [],
            &root.join("kallsyms"),
        ),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    fold_perfdata_callchains_with_symbols(bytes, FoldOptions::default(), &resolver).unwrap();
    resolver.requests.borrow().clone()
}

fn runtime_text_offset(module: &Path, source: &Path) -> u64 {
    use object::{ObjectSection as _, read::elf::SectionHeader as _};
    let runtime = std::fs::read(module).unwrap();
    let source = std::fs::read(source).unwrap();
    let object::File::Elf64(runtime) = object::File::parse(runtime.as_slice()).unwrap() else {
        panic!("ELF64 fixture");
    };
    let object::File::Elf64(source) = object::File::parse(source.as_slice()).unwrap() else {
        panic!("ELF64 fixture");
    };
    assert_eq!(runtime.build_id().unwrap(), source.build_id().unwrap());
    let text = runtime.section_by_name(".text").unwrap();
    let debug = source.section_by_name(".text").unwrap();
    assert_eq!(text.index(), debug.index());
    assert_eq!(
        debug.elf_section_header().sh_type(source.endian()),
        object::elf::SHT_NOBITS
    );
    assert_eq!(
        text.elf_section_header().sh_type(runtime.endian()),
        object::elf::SHT_PROGBITS
    );
    let offset = text.elf_section_header().sh_offset(runtime.endian());
    assert_ne!(offset, 0);
    offset
}

#[test]
fn current_module_cursor_uses_post_load_text_file_offset() {
    let (root, bytes, source) = write_native_split_debug_module_fixture();
    let offset = runtime_text_offset(&root.path().join("a.ko"), &source);
    let (script, stderr, _) = query_native_module_object(root.path());
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert_eq!(
        script.matches("cached_module_object+0x10 ([a])").count(),
        2,
        "{script}"
    );
    let requests = delivered_requests(root.path(), &bytes);
    let current = requests
        .iter()
        .find(|request| request.kernel_module_address == Some(0xffff_ffff_c100_0010))
        .unwrap();
    assert_eq!(
        current.relative_address,
        offset + 0x10,
        "current cursor uses updated pgoff: {current:?}"
    );
    assert_eq!(current.kernel_module_address, Some(0xffff_ffff_c100_0010));
}

fn move_extra_section(path: &Path, start: u64) {
    let bytes = std::fs::read(path).unwrap();
    let mut builder = object::build::elf::Builder::read(bytes.as_slice()).unwrap();
    let extra = builder
        .sections
        .iter_mut()
        .find(|section| {
            section.name.as_slice() == b".noinstr.text" || section.name.as_slice() == b".cold"
        })
        .unwrap();
    let original = extra.sh_addr;
    let id = extra.id();
    assert_eq!(original, 0xffff_ffff_c100_8000);
    assert_eq!(extra.sh_size, 0x200);
    extra.sh_addr = start;
    for symbol in builder
        .symbols
        .iter_mut()
        .filter(|symbol| symbol.section == Some(id))
    {
        symbol.st_value = start + (symbol.st_value - original);
    }
    let mut output = Vec::new();
    builder.write(&mut output).unwrap();
    std::fs::write(path, output).unwrap();
}

fn kernel_chain_without_module_event_preload(bytes: &[u8], query: u64) -> Vec<u8> {
    let header = pyroclast::perfdata::header::parse_header(bytes).unwrap();
    let offset = usize::try_from(header.data_offset).unwrap();
    let mut output = bytes[..offset].to_vec();
    for record in pyroclast::perfdata::records::iter_records(bytes, header).unwrap() {
        if record.header.record_type == PERF_RECORD_SAMPLE {
            output.extend(record_bytes_with_misc(
                PERF_RECORD_SAMPLE,
                2,
                &sample_payload_with_time(
                    0x1234,
                    11,
                    12,
                    1_000_000_001,
                    [0xffff_ffff_ffff_ff80, query],
                ),
            ));
        } else {
            output.extend(record_bytes_with_misc(
                record.header.record_type,
                record.header.misc,
                record.payload,
            ));
        }
    }
    let size = u64::try_from(output.len() - offset).unwrap();
    put_u64(&mut output, 48, size);
    output
}

#[test]
fn overlapping_child_clips_parent_but_current_cursor_keeps_parent_identity() {
    use object::{ObjectSection as _, read::elf::SectionHeader as _};
    let (root, original, source) = write_native_split_debug_module_fixture();
    let module = root.path().join("a.ko");
    rewrite_label_section(&module, true, true);
    rewrite_label_section(&source, false, false);
    let child_start = 0xffff_ffff_c100_0008;
    move_extra_section(&module, child_start);
    move_extra_section(&source, child_start);
    let runtime = std::fs::read(&module).unwrap();
    let object::File::Elf64(runtime) = object::File::parse(runtime.as_slice()).unwrap() else {
        panic!("ELF64 fixture");
    };
    let extra = runtime.section_by_name(".noinstr.text").unwrap();
    assert_eq!(extra.address(), child_start);
    assert_eq!(extra.size(), 0x200);
    let child_offset = extra.elf_section_header().sh_offset(runtime.endian());
    let text_offset = runtime_text_offset(&module, &source);
    let query = 0xffff_ffff_c100_0010;
    let bytes = kernel_chain_without_module_event_preload(&original, query);
    std::fs::write(root.path().join("perf.data"), &bytes).unwrap();
    let (script, stderr, _) = query_native_module_object(root.path());
    assert!(!stderr.contains("/kcore for kernel data"), "{stderr}");
    assert_eq!(
        script.matches("cached_module_object+0x10 ([a])").count(),
        1,
        "{script}"
    );
    assert_eq!(
        script
            .matches("selected_debug_guard+0x8 ([a].noinstr.text)")
            .count(),
        2,
        "{script}"
    );
    let requests = delivered_requests(root.path(), &bytes);
    let mut cursors = requests
        .iter()
        .filter(|request| request.kernel_module_address == Some(query));
    let current = cursors.next().unwrap();
    assert_eq!(
        current.kernel_mapping_range,
        Some((0xffff_ffff_c100_0000, child_start)),
        "retain parent ID even outside clipped interval"
    );
    assert_eq!(current.relative_address, text_offset + 0x10);
    let later = cursors
        .next()
        .expect("next cursor must select generated child");
    assert_eq!(later.relative_address, child_offset + 8);
    assert_eq!(
        later.kernel_mapping_range,
        Some((child_start, child_start + 0x200))
    );
}
