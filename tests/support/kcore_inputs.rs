use super::*;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

const WORKER: &str = "PYROCLAST_KCORE_INPUT_WORKER";
const ROOT: &str = "PYROCLAST_KCORE_INPUT_ROOT";

struct KcoreWorker(Option<std::process::Child>);

impl Drop for KcoreWorker {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn check_kcore_fifo(name: &str, file_route: bool) {
    if std::env::var(WORKER).as_deref() == Ok(name) {
        let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
        let input = root.join("perf.data");
        let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            pyroclast::symbols::RustAddr2lineResolver::new(),
            &input,
            &root,
            [],
            &root.join("kallsyms"),
        );
        let options = FoldOptions {
            inline: true,
            count_periods: true,
        };
        let actual = if file_route {
            pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(&input, options, &resolver)
        } else {
            fold_perfdata_callchains_with_symbols(
                &std::fs::read(&input).unwrap(),
                options,
                &resolver,
            )
        }
        .unwrap();
        assert_eq!(
            actual.as_bytes(),
            std::fs::read(root.join("expected.folded")).unwrap()
        );
        return;
    }

    let (root, _) = write_native_kcore_fixture("[a]");
    let kcore = root.path().join("kcore");
    std::fs::remove_file(&kcore).unwrap();
    // A rejected non-regular kcore must preserve ordinary kallsyms behavior.
    // Native perf is queried with an absent file, never with a blocking FIFO.
    let (_, _, expected) = query_native_module_kallsyms(root.path(), &[]);
    std::fs::write(root.path().join("expected.folded"), expected).unwrap();
    let path = std::ffi::CString::new(kcore.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    run_fifo_worker(name, root.path(), &kcore);
}

fn run_fifo_worker(name: &str, root: &Path, fifo: &Path) {
    let mut worker = KcoreWorker(Some(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("kcore_inputs::{name}"), "--nocapture"])
            .env(WORKER, name)
            .env(ROOT, root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut opened = false;
    let timed_out = loop {
        // Success proves a reader opened the FIFO. Closing without writing
        // releases its open/read with EOF; no infinite source is ever supplied.
        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(fifo)
        {
            Ok(writer) => {
                opened = true;
                drop(writer);
            }
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
            Err(error) => panic!("FIFO handshake failed: {error}"),
        }
        let child = worker.0.as_mut().unwrap();
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = worker.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        !timed_out && output.status.success(),
        "timeout={timed_out}, fifo_opened={opened}, status={}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed;"));
    assert!(!opened, "kcore loading opened the recording-selected FIFO");
}

#[test]
fn kcore_fifo_is_rejected_without_opening_in_byte_fold() {
    check_kcore_fifo("kcore_fifo_is_rejected_without_opening_in_byte_fold", false);
}

#[test]
fn kcore_fifo_is_rejected_without_opening_in_file_fold() {
    check_kcore_fifo("kcore_fifo_is_rejected_without_opening_in_file_fold", true);
}

#[cfg(target_arch = "x86_64")]
mod module_inputs {
    use super::*;
    use inferno::collapse::Collapse as _;

    #[derive(Clone, Copy)]
    enum Replacement {
        Fifo,
        OppositeElfType,
        BeforeLoadingOppositeElfType,
    }

    #[derive(Clone, Copy)]
    enum Route {
        Bytes,
        File,
        Scalar,
    }

    struct ReplacingModuleResolver {
        inner: pyroclast::symbols::RustAddr2lineResolver,
        replacement: RefCell<Option<std::path::PathBuf>>,
        before_loading: bool,
    }

    impl ReplacingModuleResolver {
        fn replace_selected_module(&self, requests: &[SymbolRequest]) {
            assert_eq!(requests.len(), 1, "replace the first selected module only");
            self.replace_selected_module_path(&requests[0].path);
        }

        fn replace_selected_module_path(&self, path: &Path) {
            if let Some(replacement) = self.replacement.borrow_mut().take() {
                std::fs::rename(replacement, path).unwrap();
            }
        }
    }

    impl SymbolResolver for ReplacingModuleResolver {
        fn selected_object_module_metadata(
            &self,
            path: &Path,
            module: &SymbolRequest,
        ) -> Option<std::sync::Arc<pyroclast::symbols::KernelModuleObjectMetadata>> {
            if self.before_loading {
                self.replace_selected_module_path(path);
            }
            self.inner.selected_object_module_metadata(path, module)
        }

        fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
            if self.before_loading {
                self.replace_selected_module(requests);
            }
            let result = self.inner.resolve_batch(requests)?;
            self.replace_selected_module(requests);
            Ok(result)
        }

        fn resolve_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            if self.before_loading {
                self.replace_selected_module(requests);
            }
            let result = self.inner.resolve_frame_batch_with_metadata(requests)?;
            self.replace_selected_module(requests);
            Ok(result)
        }
    }

    fn check_module_replacement(name: &str, route: Route, shared: bool, replacement: Replacement) {
        if std::env::var(WORKER).as_deref() == Ok(name) {
            let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
            let input = root.join("perf.data");
            let resolver = perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
                ReplacingModuleResolver {
                    inner: pyroclast::symbols::RustAddr2lineResolver::new(),
                    replacement: RefCell::new(Some(root.join("replacement"))),
                    before_loading: matches!(
                        replacement,
                        Replacement::BeforeLoadingOppositeElfType
                    ),
                },
                &input,
                &root,
                [],
                &root.join("kallsyms"),
            );
            let options = FoldOptions {
                inline: true,
                count_periods: true,
            };
            let actual = match route {
                Route::File => pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(
                    &input, options, &resolver,
                ),
                Route::Bytes => fold_perfdata_callchains_with_symbols(
                    &std::fs::read(&input).unwrap(),
                    options,
                    &resolver,
                ),
                Route::Scalar => {
                    check_scalar_module(&resolver, &input, shared);
                    return;
                }
            }
            .unwrap();
            assert!(resolver.object_resolver().replacement.borrow().is_none());
            assert_eq!(
                actual,
                std::fs::read_to_string(root.join("expected.folded")).unwrap(),
                "replacement must not change the selected module's section maps"
            );
            return;
        }

        let (root, _) = write_native_cached_module_fixture(shared, false);
        let fifo = root.path().join("watch.fifo");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let destination = root.path().join("replacement");
        match replacement {
            Replacement::Fifo => std::fs::hard_link(&fifo, &destination).unwrap(),
            Replacement::OppositeElfType => {
                let mut bytes = std::fs::read(root.path().join("module.elf")).unwrap();
                let elf_type = if shared {
                    object::elf::ET_EXEC
                } else {
                    object::elf::ET_DYN
                };
                bytes[16..18].copy_from_slice(&elf_type.to_le_bytes());
                std::fs::write(&destination, bytes).unwrap();
            }
            Replacement::BeforeLoadingOppositeElfType => {}
        }
        if matches!(replacement, Replacement::BeforeLoadingOppositeElfType) {
            use std::fmt::Write as _;
            let bytes = std::fs::read(root.path().join("module.elf")).unwrap();
            let object = object::File::parse(bytes.as_slice()).unwrap();
            let id =
                object
                    .build_id()
                    .unwrap()
                    .unwrap()
                    .iter()
                    .fold(String::new(), |mut hex, byte| {
                        write!(hex, "{byte:02x}").unwrap();
                        hex
                    });
            let cache =
                pyroclast::symbols::perf_build_id_elf_path(&root.path().join(".debug"), &id);
            compile_module_replacement(root.path(), &destination, &id, shared);
            let backup = root.path().join("classified-original");
            std::fs::rename(&cache, &backup).unwrap();
            std::fs::copy(&destination, &cache).unwrap();
            record_module_expected_folded(root.path());
            std::fs::rename(backup, cache).unwrap();
        } else {
            record_module_expected_folded(root.path());
        }
        run_fifo_worker(name, root.path(), &fifo);
    }

    fn compile_module_replacement(root: &Path, destination: &Path, id: &str, shared: bool) {
        let compiled = Command::new("cc")
            .args([
                "-nostdlib",
                if shared { "-no-pie" } else { "-shared" },
                "-Wl,-e,cached_module_object",
                "-Wl,-Ttext=0xffffffffc1000000",
            ])
            .arg(format!("-Wl,--build-id=0x{id}"))
            .arg(root.join("module.S"))
            .arg("-o")
            .arg(destination)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{compiled:?}");
    }

    fn record_module_expected_folded(root: &Path) {
        // perf symbol-elf.c:symsrc__init retains ss->ehdr with ss->elf/fd;
        // symbol.c:do_validate_kcore_modules_cb validates the resulting maps.
        // Query the actual symbol-load selection, not its later replacement.
        let native = Command::new("perf")
            .arg("--buildid-dir")
            .arg(root.join(".debug"))
            .args(["script", "--force", "--kallsyms"])
            .arg(root.join("kallsyms"))
            .arg("-i")
            .arg(root.join("perf.data"))
            .env("DEBUGINFOD_URLS", "")
            .output()
            .unwrap();
        assert!(native.status.success(), "{native:?}");
        assert!(String::from_utf8_lossy(&native.stdout).contains("cached_module_object+0x10"));
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::default()
            .collapse(native.stdout.as_slice(), &mut expected)
            .unwrap();
        std::fs::write(root.join("expected.folded"), expected).unwrap();
    }

    fn check_scalar_module(
        resolver: &pyroclast::symbols::PerfSymbolResolver<ReplacingModuleResolver>,
        input: &Path,
        shared: bool,
    ) {
        use std::fmt::Write as _;

        let bytes = std::fs::read(input).unwrap();
        let summary = summarize_perfdata(&bytes).unwrap();
        let mapping = summary
            .mmap_table
            .resolve_ref(11, 0xffff_ffff_c100_0010)
            .unwrap();
        let build_id = mapping
            .build_id
            .unwrap()
            .iter()
            .fold(String::new(), |mut hex, byte| {
                write!(hex, "{byte:02x}").unwrap();
                hex
            });
        let module = SymbolRequest {
            kernel_module_address: None,
            path: mapping.path.into(),
            relative_address: mapping.relative_address,
            kernel_mapping_range: Some((mapping.start, mapping.end)),
            build_id: Some(build_id),
            file_identity: mapping.file_identity,
            kernel_relocation: mapping.kernel_relocation,
        };
        let requests = std::slice::from_ref(&module);
        assert_eq!(
            resolver.resolve_batch(requests).unwrap(),
            [Some("cached_module_object".into())]
        );
        assert!(resolver.object_resolver().replacement.borrow().is_none());
        assert_eq!(
            resolver.resolve_batch(requests).unwrap(),
            [Some(
                if shared {
                    "cached_module_object"
                } else {
                    "first+0x10"
                }
                .into()
            )],
            "later scalar cursors must retain the selected module's section maps"
        );
    }

    #[test]
    fn selected_module_fifo_replacement_is_not_opened_in_byte_fold() {
        check_module_replacement(
            "module_inputs::selected_module_fifo_replacement_is_not_opened_in_byte_fold",
            Route::Bytes,
            false,
            Replacement::Fifo,
        );
    }

    #[test]
    fn selected_module_fifo_replacement_is_not_opened_in_file_fold() {
        check_module_replacement(
            "module_inputs::selected_module_fifo_replacement_is_not_opened_in_file_fold",
            Route::File,
            false,
            Replacement::Fifo,
        );
    }

    #[test]
    fn selected_dynamic_section_maps_survive_exec_replacement_in_byte_fold() {
        check_module_replacement(
            "module_inputs::selected_dynamic_section_maps_survive_exec_replacement_in_byte_fold",
            Route::Bytes,
            true,
            Replacement::OppositeElfType,
        );
    }

    #[test]
    fn selected_dynamic_section_maps_survive_exec_replacement_in_file_fold() {
        check_module_replacement(
            "module_inputs::selected_dynamic_section_maps_survive_exec_replacement_in_file_fold",
            Route::File,
            true,
            Replacement::OppositeElfType,
        );
    }

    #[test]
    fn selected_text_only_maps_survive_shared_replacement_in_byte_fold() {
        check_module_replacement(
            "module_inputs::selected_text_only_maps_survive_shared_replacement_in_byte_fold",
            Route::Bytes,
            false,
            Replacement::OppositeElfType,
        );
    }

    #[test]
    fn selected_text_only_maps_survive_shared_replacement_in_file_fold() {
        check_module_replacement(
            "module_inputs::selected_text_only_maps_survive_shared_replacement_in_file_fold",
            Route::File,
            false,
            Replacement::OppositeElfType,
        );
    }

    #[test]
    fn selected_dynamic_section_maps_survive_exec_replacement_in_scalar_resolution() {
        check_module_replacement(
            "module_inputs::selected_dynamic_section_maps_survive_exec_replacement_in_scalar_resolution",
            Route::Scalar,
            true,
            Replacement::OppositeElfType,
        );
    }

    #[test]
    fn selected_module_fifo_replacement_is_not_opened_in_scalar_resolution() {
        check_module_replacement(
            "module_inputs::selected_module_fifo_replacement_is_not_opened_in_scalar_resolution",
            Route::Scalar,
            false,
            Replacement::Fifo,
        );
    }

    #[test]
    fn module_path_classification_does_not_freeze_selected_section_maps_in_byte_fold() {
        check_module_replacement(
            "module_inputs::module_path_classification_does_not_freeze_selected_section_maps_in_byte_fold",
            Route::Bytes,
            false,
            Replacement::BeforeLoadingOppositeElfType,
        );
    }

    #[test]
    fn module_path_classification_does_not_freeze_selected_section_maps_in_file_fold() {
        check_module_replacement(
            "module_inputs::module_path_classification_does_not_freeze_selected_section_maps_in_file_fold",
            Route::File,
            false,
            Replacement::BeforeLoadingOppositeElfType,
        );
    }
}
