#![cfg(unix)]

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};

use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec, RealCommandRunner};
use pyroclast::symbols::{Addr2lineResolver, SymbolRequest, SymbolResolver};

struct ReplacingRunner {
    selected: PathBuf,
    replacement: PathBuf,
    in_place: bool,
    mutated: Cell<bool>,
    outputs: RefCell<Vec<CommandOutput>>,
    native: RealCommandRunner,
}

impl CommandRunner for ReplacingRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        assert_eq!(command.args[3], self.selected.to_str().unwrap());
        if !self.mutated.replace(true) {
            if self.in_place {
                std::fs::copy(&self.replacement, &self.selected)?;
            } else {
                std::fs::rename(&self.replacement, &self.selected)?;
            }
        }
        let output = run_native(&self.native, command)?;
        self.outputs.borrow_mut().push(output.clone());
        Ok(output)
    }
}

fn gnu_oracle() -> PathBuf {
    std::env::var_os("PYRO_GNU_ORACLE")
        .map(PathBuf::from)
        .expect("run native GNU tests through the repository devenv shell")
}

fn run_native(runner: &RealCommandRunner, command: &CommandSpec) -> std::io::Result<CommandOutput> {
    // Before the selected-input fix, Darwin invokes plain addr2line. Route that
    // actual execution to GNU, not the compiler's LLVM shim, to prove its race.
    let mut command = command.clone();
    if command.program == "addr2line" {
        gnu_oracle()
            .to_str()
            .unwrap()
            .clone_into(&mut command.program);
    }
    runner.run(&command)
}

fn fixture(root: &Path, name: &str) -> PathBuf {
    let source = root.join(format!("{name}.c"));
    let binary = root.join(name);
    std::fs::write(
        &source,
        format!("void {name}(void) {{ __asm__ volatile(\"nop\"); }}\n"),
    )
    .unwrap();
    let mut compiler = std::process::Command::new("cc");
    #[cfg(target_os = "linux")]
    compiler.args(["-g", "-O0", "-nostdlib", "-no-pie", "-Wl,-e,0"]);
    #[cfg(not(target_os = "linux"))]
    compiler.args(["--target=x86_64-linux-gnu", "-g", "-O0", "-c"]);
    let output = compiler
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn selected_request(path: &Path) -> SymbolRequest {
    use object::{Object, ObjectSymbol};

    let bytes = std::fs::read(path).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let address = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("selected_leaf"))
        .unwrap()
        .address();
    SymbolRequest {
        kernel_module_address: None,
        path: path.to_owned(),
        relative_address: address,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    }
}

fn independent_gnu_output(request: &SymbolRequest) -> Vec<u8> {
    let output = std::process::Command::new(gnu_oracle())
        .args(["-f", "-C", "-e"])
        .arg(&request.path)
        .arg(format!("0x{:x}", request.relative_address))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.starts_with(b"selected_leaf\n"));
    output.stdout
}

fn strip_with_debuglink(selected: &Path, debug: &Path) {
    for args in [
        vec![
            "--only-keep-debug".into(),
            selected.to_owned(),
            debug.to_owned(),
        ],
        vec!["--strip-all".into(), selected.to_owned()],
        vec![
            format!("--add-gnu-debuglink={}", debug.display()).into(),
            selected.to_owned(),
        ],
    ] {
        let output = std::process::Command::new(gnu_oracle().with_file_name("objcopy"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn resolves_selected_primary(in_place: bool, prime: bool) {
    // GNU process_file() opens -e again; BFD's debuglink and altlink probes
    // also close/reopen candidates (bfd/opncls.c). This test replaces the
    // primary at the public CommandRunner boundary, after our object selection.
    // No output normalization or symbol-name exceptions are involved.
    let root = tempfile::tempdir().unwrap();
    let selected = fixture(root.path(), "selected_leaf");
    let replacement = fixture(root.path(), "replacement_leaf");
    let request = selected_request(&selected);
    let expected_stdout = independent_gnu_output(&request);
    let runner = ReplacingRunner {
        selected,
        replacement,
        in_place,
        mutated: Cell::new(false),
        outputs: RefCell::new(Vec::new()),
        native: RealCommandRunner::default(),
    };
    let resolver = Addr2lineResolver::new(&runner);
    if prime {
        let frames = resolver
            .resolve_base_frame_batch_with_metadata(std::slice::from_ref(&request))
            .unwrap();
        assert_eq!(frames[0].frames, ["selected_leaf+0x0"]);
    }
    for _ in 0..2 {
        let names = resolver
            .resolve_batch(std::slice::from_ref(&request))
            .unwrap();
        assert_eq!(names, [Some("selected_leaf".to_owned())]);
    }
    let outputs = runner.outputs.borrow();
    assert_eq!(outputs.len(), 2);
    for output in outputs.iter() {
        assert_eq!(output.status_code, Some(0));
        assert_eq!(output.stdout, expected_stdout);
    }
}

#[test]
fn gnu_backend_retains_selected_primary_after_path_replacement() {
    resolves_selected_primary(false, true);
}

#[test]
fn gnu_backend_retains_selected_primary_after_in_place_rewrite() {
    resolves_selected_primary(true, true);
}

#[test]
fn gnu_backend_selects_primary_before_first_subprocess() {
    resolves_selected_primary(false, false);
}

#[test]
fn gnu_backend_selects_immutable_bytes_before_first_in_place_rewrite() {
    resolves_selected_primary(true, false);
}

#[test]
fn gnu_batches_share_the_selected_primary_transport() {
    struct RecordingRunner {
        commands: RefCell<Vec<CommandSpec>>,
        native: RealCommandRunner,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
            self.commands.borrow_mut().push(command.clone());
            run_native(&self.native, command)
        }
    }

    // perf addr2line.c:cmd__addr2line retains the selected DSO's input and
    // helper across requests. A sealed transport must likewise belong to the
    // selected object, not be recopied for each batch. Native output still
    // comes from independently executed GNU, without symbol-name rewrites.
    let root = tempfile::tempdir().unwrap();
    let selected = fixture(root.path(), "selected_leaf");
    let request = selected_request(&selected);
    let expected_stdout = independent_gnu_output(&request);
    let runner = RecordingRunner {
        commands: RefCell::new(Vec::new()),
        native: RealCommandRunner::default(),
    };
    let resolver = Addr2lineResolver::new(&runner);
    for _ in 0..3 {
        let symbols = resolver
            .resolve_batch(std::slice::from_ref(&request))
            .unwrap();
        assert_eq!(symbols, [Some("selected_leaf".to_owned())]);
    }
    let commands = runner.commands.borrow();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0].inherited_files.len(), 1);
    for command in &commands[1..] {
        assert_eq!(
            command.inherited_files, commands[0].inherited_files,
            "each batch must borrow the same selected transport"
        );
        let output = run_native(&runner.native, command).unwrap();
        assert_eq!(output.status_code, Some(0));
        assert_eq!(output.stdout, expected_stdout);
    }
}

#[test]
fn gnu_backend_debuglink_discovery_keeps_original_logical_directory() {
    use object::Object;

    // bfd/opncls.c:find_separate_debug_file tries the logical object's
    // directory, then .debug/, before canonical global roots. A /proc FD
    // substituted for -e would lose this file even with correct primary bytes.
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("objects with spaces");
    std::fs::create_dir(&directory).unwrap();
    let selected = fixture(&directory, "selected_leaf");
    let replacement = fixture(&directory, "replacement_leaf");
    let request = selected_request(&selected);
    let debug_directory = directory.join(".debug");
    std::fs::create_dir(&debug_directory).unwrap();
    let debug = debug_directory.join("selected.debug");
    strip_with_debuglink(&selected, &debug);
    let bytes = std::fs::read(&selected).unwrap();
    assert_eq!(
        object::File::parse(bytes.as_slice())
            .unwrap()
            .symbols()
            .count(),
        0
    );
    let expected_stdout = independent_gnu_output(&request);
    let runner = ReplacingRunner {
        selected,
        replacement,
        in_place: false,
        mutated: Cell::new(false),
        outputs: RefCell::new(Vec::new()),
        native: RealCommandRunner::default(),
    };
    let resolver = Addr2lineResolver::new(&runner);
    let frames = resolver
        .resolve_base_frame_batch_with_metadata(std::slice::from_ref(&request))
        .unwrap();
    assert!(
        frames[0].frames.is_empty(),
        "no symtab alias can mask GNU failure"
    );
    let names = resolver.resolve_batch(&[request]).unwrap();
    assert_eq!(names, [Some("selected_leaf".to_owned())]);
    let outputs = runner.outputs.borrow();
    assert_eq!(outputs[0].status_code, Some(0));
    assert_eq!(outputs[0].stdout, expected_stdout);
}

#[test]
fn gnu_backend_retains_loaded_debuglink_across_batches() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdout, Stdio};

    struct NativeSession {
        child: Child,
        stdout: BufReader<ChildStdout>,
    }
    impl NativeSession {
        fn lookup(&mut self, address: u64) -> String {
            writeln!(self.child.stdin.as_mut().unwrap(), "0x{address:x}").unwrap();
            let mut result = String::new();
            for _ in 0..2 {
                assert!(self.stdout.read_line(&mut result).unwrap() > 0);
            }
            result
        }
    }
    impl Drop for NativeSession {
        fn drop(&mut self) {
            // This unreaped Child owns the PID throughout kill/wait.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    // perf addr2line.c:300-315 keeps one helper per DSO. GNU
    // translate_addresses:287-430 keeps its BFD/debuglink inputs across
    // stdin requests. Compare that real retained process, not saved output.
    let root = tempfile::tempdir().unwrap();
    let selected = fixture(root.path(), "selected_leaf");
    let request = selected_request(&selected);
    let debug = root.path().join("selected.debug");
    strip_with_debuglink(&selected, &debug);
    let mut child = std::process::Command::new(gnu_oracle())
        .args(["-f", "-C", "-e"])
        .arg(&selected)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let mut native = NativeSession { child, stdout };
    let expected = native.lookup(request.relative_address);
    assert!(expected.starts_with("selected_leaf\n"));
    let runner = RealCommandRunner::default();
    let resolver = Addr2lineResolver::new(&runner);
    assert_eq!(
        resolver
            .resolve_batch(std::slice::from_ref(&request))
            .unwrap(),
        [Some("selected_leaf".to_owned())]
    );
    std::fs::remove_file(debug).unwrap();
    assert_eq!(native.lookup(request.relative_address), expected);
    assert_eq!(
        resolver.resolve_batch(&[request]).unwrap(),
        [Some("selected_leaf".to_owned())],
        "a later batch must retain the already loaded debuglink"
    );
}

#[test]
fn gnu_sessions_preserve_distinct_objects_unknowns_and_batch_order() {
    let root = tempfile::tempdir().unwrap();
    let first = fixture(root.path(), "selected_leaf");
    let second = fixture(root.path(), "replacement_leaf");
    let request = selected_request(&first);
    let other = SymbolRequest {
        path: second.clone(),
        ..request.clone()
    };
    let unknown = SymbolRequest {
        relative_address: u64::MAX,
        ..request.clone()
    };
    let first_debug = root.path().join("first.debug");
    let second_debug = root.path().join("second.debug");
    strip_with_debuglink(&first, &first_debug);
    strip_with_debuglink(&second, &second_debug);
    let runner = RealCommandRunner::default();
    let resolver = Addr2lineResolver::new(&runner);
    assert_eq!(
        resolver
            .resolve_batch(&[
                request.clone(),
                unknown.clone(),
                other.clone(),
                request.clone()
            ])
            .unwrap(),
        [
            Some("selected_leaf".to_owned()),
            None,
            Some("replacement_leaf".to_owned()),
            Some("selected_leaf".to_owned())
        ]
    );
    std::fs::remove_file(first_debug).unwrap();
    std::fs::remove_file(second_debug).unwrap();
    assert_eq!(
        resolver.resolve_batch(&[other, request, unknown]).unwrap(),
        [
            Some("replacement_leaf".to_owned()),
            Some("selected_leaf".to_owned()),
            None
        ]
    );
}

#[test]
fn gnu_session_failure_is_not_restarted_with_different_auxiliary_inputs() {
    struct FailingRunner {
        starts: Cell<usize>,
        native: RealCommandRunner,
    }
    impl CommandRunner for FailingRunner {
        fn run(&self, _: &CommandSpec) -> std::io::Result<CommandOutput> {
            panic!("a failed persistent protocol must not fall back to another process");
        }

        fn start_session(
            &self,
            _: &CommandSpec,
        ) -> std::io::Result<Option<pyroclast::process::CommandSession>> {
            self.starts.set(self.starts.get() + 1);
            self.native.start_session(
                &CommandSpec::new("sh").args(["-c", "read -r address; printf 'partial\\n'"]),
            )
        }
    }

    let root = tempfile::tempdir().unwrap();
    let selected = fixture(root.path(), "selected_leaf");
    let request = selected_request(&selected);
    let runner = FailingRunner {
        starts: Cell::new(0),
        native: RealCommandRunner::default(),
    };
    let resolver = Addr2lineResolver::new(&runner);
    let error = resolver
        .resolve_batch(std::slice::from_ref(&request))
        .unwrap_err();
    assert!(error.contains("1/2 response lines"), "{error}");
    assert_eq!(resolver.resolve_batch(&[request]).unwrap_err(), error);
    assert_eq!(runner.starts.get(), 1);
}
