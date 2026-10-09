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
