#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use framehop::x86_64::Reg;
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use pyroclast::perfdata::unwind::{FramehopUnwinder, PerfUserRegs, PerfX86_64Regs};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const CHILD_CASE: &str = "PYROCLAST_LOADER_UNWIND_CHILD";
const CHILD_ROOT: &str = "PYROCLAST_LOADER_UNWIND_ROOT";
const SUCCESS: &str = "loader-unwind-input-ok";
const DEADLINE: Duration = Duration::from_secs(15);
const WORD: u64 = 0x1234_5678_9abc_def0;

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn wait(&mut self, deadline: Instant) -> ExitStatus {
        loop {
            if let Some(status) = self
                .0
                .as_mut()
                .expect("owned child")
                .try_wait()
                .expect("poll child")
            {
                self.0.take();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "child exceeded 15-second deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_bounded(command: &mut Command, log: &Path) -> String {
    let output = File::create(log).expect("create child log");
    command
        .stdin(Stdio::null())
        .stdout(output.try_clone().expect("clone child log"))
        .stderr(output);
    let deadline = Instant::now() + DEADLINE;
    let mut child = OwnedChild(Some(command.spawn().expect("spawn child")));
    let status = child.wait(deadline);
    let output = fs::read_to_string(log).expect("read child log");
    assert!(status.success(), "child exited with {status}:\n{output}");
    output
}

fn compile_fixture(root: &Path) {
    let source = root.join("unwind.S");
    fs::write(
        &source,
        ".text\n\
         .globl leaf\n.type leaf,@function\nleaf:\n.cfi_startproc\n\
         .cfi_def_cfa %rsp,8\n.cfi_offset %rip,-8\n\
         .fill 16,1,0x90\nret\n.cfi_endproc\n.size leaf,.-leaf\n\
         .p2align 5\n.globl caller\n.type caller,@function\ncaller:\n\
         .cfi_startproc\n.cfi_def_cfa %rsp,8\n.cfi_undefined %rip\n\
         .fill 16,1,0x90\nret\n.cfi_endproc\n.size caller,.-caller\n\
         .data\n.balign 8\n.globl mapped_word\n.type mapped_word,@object\n\
         mapped_word:\n.quad 0x123456789abcdef0\n.size mapped_word,8\n\
         .section .note.GNU-stack,\"\",@progbits\n",
    )
    .expect("write assembly fixture");
    run_bounded(
        Command::new("cc")
            .args([
                "-nostdlib",
                "-no-pie",
                "-g",
                "-Wl,-e,leaf",
                "-Wl,--eh-frame-hdr",
            ])
            .arg(&source)
            .arg("-o")
            .arg(root.join("control")),
        &root.join("cc.log"),
    );
    fs::copy(root.join("control"), root.join("subject")).expect("copy separate subject inode");
}

fn isolated(name: &str, test: fn(&Path)) {
    if let Some(child_case) = std::env::var_os(CHILD_CASE) {
        assert_eq!(
            child_case, name,
            "child must execute exactly its selected test"
        );
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // Only the re-executed child changes its resource limits.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) },
            0
        );
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child fixture root"));
        assert_valid_control(&Fixture::read(root.join("control")));
        test(&root);
        println!("\n{SUCCESS}:{name}");
        return;
    }

    let root = tempfile::tempdir().expect("fixture directory");
    compile_fixture(root.path());
    let output = run_bounded(
        Command::new(std::env::current_exe().expect("integration test executable"))
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD_CASE, name)
            .env(CHILD_ROOT, root.path()),
        &root.path().join("child.log"),
    );
    assert!(
        output
            .lines()
            .any(|line| line == format!("{SUCCESS}:{name}")),
        "child did not complete the selected regression:\n{output}"
    );
}

struct Fixture {
    path: PathBuf,
    start: u64,
    len: u64,
    pgoff: u64,
    leaf: u64,
    caller: u64,
    word: u64,
}

impl Fixture {
    fn read(path: PathBuf) -> Self {
        let bytes = fs::read(&path).expect("read fixture");
        let object = object::File::parse(&bytes[..]).expect("parse fixture");
        assert_eq!(object.kind(), object::ObjectKind::Executable);
        for name in [".eh_frame", ".eh_frame_hdr"] {
            assert!(object.section_by_name(name).expect("CFI section").size() > 0);
        }
        let symbol = |name| {
            object
                .symbols()
                .find(|symbol| symbol.name() == Ok(name))
                .expect("fixture symbol")
                .address()
        };
        let leaf = symbol("leaf");
        let segment = object
            .segments()
            .find(|segment| segment.address() <= leaf && leaf < segment.address() + segment.size())
            .expect("leaf PT_LOAD");
        let word = symbol("mapped_word");
        assert!(object.segments().any(|segment| {
            segment.address() <= word && word + 8 <= segment.address() + segment.file_range().1
        }));
        Self {
            path,
            start: segment.address(),
            len: segment.size(),
            pgoff: segment.file_range().0,
            leaf,
            caller: symbol("caller"),
            word,
        }
    }

    fn register(&self) -> FramehopUnwinder {
        let mut unwinder = FramehopUnwinder::new();
        assert!(
            unwinder
                .add_object_mapping(&self.path, self.start, self.len, self.pgoff)
                .expect("register fixture mapping")
        );
        assert!(unwinder.has_reported_module_for_ip(self.leaf + 1));
        assert!(unwinder.has_unwind_info_for_ip(self.leaf + 1));
        unwinder
    }

    fn unwind(&self, unwinder: &mut FramehopUnwinder) -> Vec<u64> {
        let sp = 0x7000_0000;
        let mut registers = [0; 16];
        registers[Reg::RSP as usize] = sp;
        let regs = PerfUserRegs::X86_64(PerfX86_64Regs {
            ip: self.leaf + 1,
            sp,
            bp: 0,
            registers,
        });
        let mut stack = [0; 64];
        stack[..8].copy_from_slice(&(self.caller + 1).to_le_bytes());
        unwinder.unwind_stack(regs, &stack, 8)
    }

    fn truncate(&self) {
        let before = fs::metadata(&self.path).expect("fixture metadata");
        OpenOptions::new()
            .write(true)
            .open(&self.path)
            .expect("open same inode for truncation")
            .set_len(0)
            .expect("truncate fixture inode");
        let after = fs::metadata(&self.path).expect("truncated metadata");
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(after.len(), 0);
    }
}

fn assert_valid_control(fixture: &Fixture) {
    let mut unwinder = fixture.register();
    assert_eq!(
        fixture.unwind(&mut unwinder),
        [fixture.leaf + 1, fixture.caller]
    );
    assert_eq!(unwinder.read_process_u64(fixture.word), Some(WORD));
}

#[test]
fn fifo_mapping_is_rejected_without_blocking_open() {
    isolated("fifo_mapping_is_rejected_without_blocking_open", |root| {
        let fifo = root.join("object.fifo");
        let name = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path");
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let worker_fifo = fifo.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut unwinder = FramehopUnwinder::new();
            let result = unwinder.add_object_mapping(&worker_fifo, 0x0040_0000, 0x1000, 0);
            sender
                .send((result, unwinder.module_count()))
                .expect("send loader result");
        });
        // perf util/unwind-libdw.c rejects non-regular files before report_elf.
        // A nonblocking writer detects a blocked reader and releases it with EOF.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut opened = false;
        let (result, modules) = loop {
            match receiver.try_recv() {
                Ok(result) => break result,
                Err(mpsc::TryRecvError::Disconnected) => panic!("loader worker panicked"),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if !opened {
                match OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&fifo)
                {
                    Ok(writer) => {
                        opened = true;
                        drop(writer);
                    }
                    Err(error) => assert_eq!(error.raw_os_error(), Some(libc::ENXIO)),
                }
            }
            assert!(Instant::now() < deadline, "FIFO loader failed to return");
            std::thread::sleep(Duration::from_millis(10));
        };
        worker.join().expect("join loader worker");
        assert!(!opened, "loader opened FIFO for reading");
        assert!(!matches!(result, Ok(true)), "FIFO registered as an object");
        assert_eq!(modules, 0);
    });
}

#[test]
fn registered_cfi_survives_inode_truncation_before_first_unwind() {
    isolated(
        "registered_cfi_survives_inode_truncation_before_first_unwind",
        |root| {
            let fixture = Fixture::read(root.join("subject"));
            // The control used another inode and unwinder; this cache is still cold.
            let mut unwinder = fixture.register();
            fixture.truncate();
            assert_eq!(
                fixture.unwind(&mut unwinder),
                [fixture.leaf + 1, fixture.caller]
            );
        },
    );
}

#[test]
fn truncated_mapping_word_is_unavailable_instead_of_faulting() {
    isolated(
        "truncated_mapping_word_is_unavailable_instead_of_faulting",
        |root| {
            let fixture = Fixture::read(root.join("subject"));
            let unwinder = fixture.register();
            fixture.truncate();
            // perf's access_dso_mem requires a complete word from the backing file.
            assert_eq!(unwinder.read_process_u64(fixture.word), None);
        },
    );
}
