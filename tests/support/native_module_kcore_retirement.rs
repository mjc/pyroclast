use super::super::*;
use object::read::elf::ProgramHeader as _;
use pyroclast::symbols::{KernelModuleObjectMetadata, SelectedObjectResolver, SymbolizerKind};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

struct ObservedModuleObjects<R> {
    inner: R,
    loaded: Rc<RefCell<Vec<PathBuf>>>,
}

impl<R: SymbolResolver> SymbolResolver for ObservedModuleObjects<R> {
    fn object_build_id(&self, path: &Path) -> Option<Vec<u8>> {
        self.inner.object_build_id(path)
    }

    fn selected_object_module_metadata(
        &self,
        path: &Path,
        module: &SymbolRequest,
    ) -> Option<Arc<KernelModuleObjectMetadata>> {
        let metadata = self.inner.selected_object_module_metadata(path, module)?;
        self.loaded.borrow_mut().push(path.to_path_buf());
        Some(metadata)
    }

    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.inner.resolve_batch(requests)
    }

    fn resolve_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        self.inner.resolve_frame_batch_with_metadata(requests)
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        self.inner.resolve_base_frame_batch_with_metadata(requests)
    }
}

fn core_first_recording(original: &[u8]) -> Vec<u8> {
    let header = pyroclast::perfdata::header::parse_header(original).unwrap();
    let offset = usize::try_from(header.data_offset).unwrap();
    let mut bytes = original[..offset].to_vec();
    let queries = [0xffff_ffff_8100_0010, 0xffff_ffff_c100_0010, LABEL_SAMPLE];
    let mut index = 0;
    for record in pyroclast::perfdata::records::iter_records(original, header).unwrap() {
        let replacement;
        let payload = if record.header.record_type == PERF_RECORD_SAMPLE {
            let ip = queries[index];
            replacement = sample_payload_with_time(
                ip,
                11,
                12,
                1_000_000_000 + u64::try_from(index).unwrap(),
                [0xffff_ffff_ffff_ff80, ip],
            );
            index += 1;
            replacement.as_slice()
        } else {
            record.payload
        };
        bytes.extend(record_bytes_with_misc(
            record.header.record_type,
            record.header.misc,
            payload,
        ));
    }
    assert_eq!(index, queries.len());
    let size = u64::try_from(bytes.len() - offset).unwrap();
    put_u64(&mut bytes, 48, size);
    bytes
}

fn narrow_kcore_module_span(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let object::File::Elf64(elf) = object::File::parse(bytes.as_slice()).unwrap() else {
        panic!("ELF64 kcore fixture");
    };
    let header = &elf.elf_program_headers()[1];
    let endian = elf.endian();
    assert_eq!(header.p_type(endian), object::elf::PT_LOAD);
    assert_eq!(header.p_vaddr(endian), 0xffff_ffff_c100_0000);
    assert_eq!(header.p_filesz(endian), 0x2_0000);
    assert_eq!(header.p_memsz(endian), 0x2_0000);
    // The existing ELF64 fixture has two 56-byte program headers at offset 64.
    put_u64(&mut bytes, 64 + 56 + 32, 0x4000);
    put_u64(&mut bytes, 64 + 56 + 40, 0x4000);
    let object::File::Elf64(elf) = object::File::parse(bytes.as_slice()).unwrap() else {
        panic!("narrowed ELF64 kcore fixture");
    };
    let header = &elf.elf_program_headers()[1];
    assert_eq!(header.p_filesz(elf.endian()), 0x4000);
    assert_eq!(header.p_memsz(elf.endian()), 0x4000);
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn native_active_kcore_does_not_publish_retired_module_children() {
    let (root, original, source) = write_native_split_debug_module_fixture();
    let module = root.path().join("a.ko");
    rewrite_label_section(&module, true, true);
    rewrite_label_section(&source, false, false);
    assert_label_source_pair(
        &std::fs::read(&module).unwrap(),
        &std::fs::read(&source).unwrap(),
        true,
    );
    narrow_kcore_module_span(&root.path().join("kcore"));
    let bytes = core_first_recording(&original);
    let input = root.path().join("perf.data");
    std::fs::write(&input, &bytes).unwrap();
    let (script, stderr, native) = query_native_module_object(root.path());
    assert!(
        stderr.contains("/kcore for kernel data"),
        "{script}\n{stderr}"
    );
    assert!(
        script.contains("_stext+0x10 ([kernel.kallsyms])"),
        "{script}"
    );
    assert!(
        script.contains("first+0x10 ([kernel.kallsyms])"),
        "{script}"
    );
    assert!(
        script.contains(&format!("{LABEL_SAMPLE:x} [unknown] ([unknown])")),
        "{script}\n{stderr}"
    );
    assert!(!script.contains("[a].noinstr.text"), "{script}");
    assert!(
        !stderr.contains("symbol__new: selected_debug_guard "),
        "{stderr}"
    );
    assert!(
        !stderr.contains("symbol__new: runtime_only_guard "),
        "{stderr}"
    );
    assert_eq!(
        native, b"worker;[unknown] 1\nworker;_stext 1\nworker;first 1\n",
        "{script}\n{stderr}"
    );
    let runner = pyroclast::process::RealCommandRunner::default();
    for symbolizer in [SymbolizerKind::RustAddr2line, SymbolizerKind::Addr2line] {
        for inline in [false, true] {
            for file_route in [false, true] {
                let loaded = Rc::new(RefCell::new(Vec::new()));
                let objects = ObservedModuleObjects {
                    inner: SelectedObjectResolver::new(&runner, symbolizer),
                    loaded: Rc::clone(&loaded),
                };
                let resolver =
                    perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                        objects,
                        &input,
                        root.path(),
                        [],
                        &root.path().join("kallsyms"),
                    );
                let options = FoldOptions {
                    inline,
                    count_periods: true,
                };
                let actual = if file_route {
                    pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                        &input, options, &resolver,
                    )
                } else {
                    fold_perfdata_callchains_with_symbols(&bytes, options, &resolver)
                }
                .unwrap();
                assert_eq!(
                    actual.as_bytes(),
                    native,
                    "{symbolizer:?} inline={inline} file={file_route}; successful module metadata={:?}\nnative={script}\n{stderr}",
                    loaded.borrow()
                );
                assert!(
                    loaded.borrow().is_empty(),
                    "retired module metadata: {:?}",
                    loaded.borrow()
                );
            }
        }
    }
}
