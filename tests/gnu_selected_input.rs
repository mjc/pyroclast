#![cfg(target_os = "linux")]

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
        let output = self.native.run(command)?;
        self.outputs.borrow_mut().push(output.clone());
        Ok(output)
    }
}

fn fixture(root: &Path, name: &str) -> PathBuf {
    let source = root.join(format!("{name}.c"));
    let binary = root.join(name);
    std::fs::write(
        &source,
        format!("void {name}(void) {{ __asm__ volatile(\"nop\"); }}\n"),
    )
    .unwrap();
    let output = std::process::Command::new("cc")
        .args(["-g", "-O0", "-nostdlib", "-no-pie", "-Wl,-e,0"])
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
        path: path.to_owned(),
        relative_address: address,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    }
}

fn independent_gnu_output(request: &SymbolRequest) -> Vec<u8> {
    let output = std::process::Command::new("addr2line")
        .args(["-f", "-C", "-e"])
        .arg(&request.path)
        .arg(format!("0x{:x}", request.relative_address))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.starts_with(b"selected_leaf\n"));
    output.stdout
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
            self.native.run(command)
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
        let output = runner.native.run(command).unwrap();
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
    for args in [
        vec!["--only-keep-debug".into(), selected.clone(), debug.clone()],
        vec!["--strip-all".into(), selected.clone()],
        vec![
            format!("--add-gnu-debuglink={}", debug.display()).into(),
            selected.clone(),
        ],
    ] {
        let output = std::process::Command::new("objcopy")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
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
