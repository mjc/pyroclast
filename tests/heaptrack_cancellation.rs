#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use pyroclast::backends::heaptrack::HeaptrackBackend;
use pyroclast::backends::offcpu::{OffcpuBackend, OffcpuMethod};
use pyroclast::backends::{ProfileRequest, ProfilerBackend, WorkloadOutcome};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind, SymbolizerKind};
use pyroclast::parsers::heaptrack::parse_heaptrack_summary;
use pyroclast::process::{CommandOutput, CommandPurpose, CommandRunner, CommandSpec};

const ACTOR_MODE: &str = "PYROCLAST_HEAPTRACK_ACTOR_MODE";
const ACTOR_READY: &str = "PYROCLAST_HEAPTRACK_ACTOR_READY";
const ACTOR_RELEASE: &str = "PYROCLAST_HEAPTRACK_ACTOR_RELEASE";
const ACTOR_SIGNAL: &str = "PYROCLAST_HEAPTRACK_ACTOR_SIGNAL";

#[derive(Clone, Debug)]
struct ProcessIdentity {
    pid: i32,
    start: String,
    parent: i32,
    group: i32,
    command: Vec<u8>,
}

impl ProcessIdentity {
    fn read(pid: i32) -> Option<Self> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
        Some(Self {
            pid,
            start: fields.get(19)?.to_string(),
            parent: fields.get(1)?.parse().ok()?,
            group: fields.get(2)?.parse().ok()?,
            command: std::fs::read(format!("/proc/{pid}/cmdline")).ok()?,
        })
    }

    fn same_process(&self) -> bool {
        Self::read(self.pid).is_some_and(|current| {
            current.start == self.start
                && current.group == self.group
                && current.command == self.command
        })
    }

    fn still_matches(&self) -> bool {
        Self::read(self.pid).is_some_and(|current| {
            current.start == self.start
                && current.parent == self.parent
                && current.group == self.group
                && current.command == self.command
        })
    }

    fn signal(&self, signal: i32) -> bool {
        if self.same_process() {
            // SAFETY: PID, start time, and full command line still identify
            // the test-owned process observed before signaling.
            unsafe { libc::kill(self.pid, signal) == 0 }
        } else {
            false
        }
    }
}

struct Probe {
    child: Child,
    leader: ProcessIdentity,
    heaptrack: PathBuf,
    recorder: Option<ProcessIdentity>,
    actor: Option<ProcessIdentity>,
}

struct ChildGuard {
    child: Option<Child>,
    recorder_wrapper: Option<PathBuf>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            recorder_wrapper: None,
        }
    }

    fn track_recorder(mut self, wrapper: PathBuf) -> Self {
        self.recorder_wrapper = Some(wrapper);
        self
    }

    fn into_inner(mut self) -> Child {
        self.child.take().expect("owned child")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let (Some(child), Some(wrapper)) = (&self.child, &self.recorder_wrapper) {
            let parent = i32::try_from(child.id()).ok();
            if let Some(parent) = parent {
                let recorder = std::fs::read_dir("/proc").ok().and_then(|entries| {
                    entries
                        .filter_map(Result::ok)
                        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
                        .filter_map(ProcessIdentity::read)
                        .find(|process| {
                            process.parent == parent
                                && process.group == process.pid
                                && process.command.split(|byte| *byte == 0).any(|argument| {
                                    argument == wrapper.as_os_str().as_encoded_bytes()
                                })
                        })
                });
                if let Some(recorder) = recorder
                    && recorder.still_matches()
                {
                    // SAFETY: The wrapper argv, parent, PID, start time, and
                    // process group identify this guard's nested recorder.
                    unsafe { libc::kill(-recorder.group, libc::SIGKILL) };
                }
            }
        }
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Probe {
    fn exit_code(&self) -> Option<i32> {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: The test owns this child; WNOWAIT keeps its PID pinned.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        // SAFETY: Successful waitid initialized info.
        let info = unsafe { info.assume_init() };
        // SAFETY: A nonzero PID means waitid populated the status fields.
        if unsafe { info.si_pid() } == 0 {
            None
        } else {
            // SAFETY: The status fields are initialized for a reported child.
            let status = unsafe { info.si_status() };
            Some(if info.si_code == libc::CLD_EXITED {
                status
            } else {
                128 + status
            })
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let recorder = self.recorder.clone().or_else(|| {
            std::fs::read_dir("/proc")
                .ok()?
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
                .filter_map(ProcessIdentity::read)
                .find(|process| {
                    process.parent == self.leader.pid
                        && process.group == process.pid
                        && process.command.split(|byte| *byte == 0).any(|argument| {
                            argument == self.heaptrack.as_os_str().as_encoded_bytes()
                        })
                })
        });
        if let Some(recorder) = recorder
            && recorder.group == recorder.pid
            && recorder.parent == self.leader.pid
            && recorder.still_matches()
            && recorder
                .command
                .split(|byte| *byte == 0)
                .any(|argument| argument == self.heaptrack.as_os_str().as_encoded_bytes())
        {
            // SAFETY: The verified heaptrack wrapper pins its test-owned group.
            unsafe { libc::kill(-recorder.group, libc::SIGKILL) };
        }
        if let Some(actor) = &self.actor {
            let _ = actor.signal(libc::SIGKILL);
        }
        if self.leader.group == self.leader.pid && self.leader.same_process() {
            // SAFETY: The unreaped child pins this test-created process group.
            unsafe { libc::kill(-self.leader.group, libc::SIGKILL) };
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_until(mut ready: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !ready() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

fn path_on_path(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
        .map(|directory| directory.join(name))
        .find(|path| {
            path.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .and_then(|path| path.canonicalize().ok())
        .unwrap_or_else(|| panic!("{name} is not installed on PATH"))
}

fn actor_identity(path: &Path) -> Option<ProcessIdentity> {
    let pid = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    ProcessIdentity::read(pid)
}

fn spawn_profile(root: &Path, mode: &str) -> Probe {
    let actor_exe = std::env::current_exe().expect("test executable");
    let heaptrack = path_on_path("heaptrack");
    let heaptrack_print = path_on_path("heaptrack_print");
    assert_eq!(heaptrack.parent(), heaptrack_print.parent());
    let out = root.join("run");
    let mut command = Command::new(env!("CARGO_BIN_EXE_pyroclast"));
    command
        .args(["memory", "--json", "--out"])
        .arg(&out)
        .arg("--")
        .arg(&actor_exe)
        .args(["--exact", "heaptrack_actor", "--nocapture"])
        .env(ACTOR_MODE, mode)
        .env(ACTOR_READY, root.join("actor.ready"))
        .env(ACTOR_RELEASE, root.join("actor.release"))
        .env(ACTOR_SIGNAL, root.join("actor.signal"))
        .process_group(0)
        .stdout(Stdio::from(
            std::fs::File::create(root.join("stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(root.join("stderr")).unwrap(),
        ));

    let child = ChildGuard::new(command.spawn().expect("start Pyroclast"))
        .track_recorder(heaptrack.clone());
    let leader = ProcessIdentity::read(i32::try_from(child.child.as_ref().unwrap().id()).unwrap())
        .expect("read Pyroclast identity");
    let mut probe = Probe {
        child: child.into_inner(),
        leader,
        heaptrack: heaptrack.clone(),
        recorder: None,
        actor: None,
    };
    let ready_path = root.join("actor.ready");
    assert!(
        wait_until(
            || actor_identity(&ready_path).is_some_and(|actor| {
                actor
                    .command
                    .split(|byte| *byte == 0)
                    .any(|arg| arg == actor_exe.as_os_str().as_encoded_bytes())
            }),
            Duration::from_secs(15)
        ),
        "native actor did not reach its allocation barrier; status={:?}; stderr={}",
        probe.exit_code(),
        std::fs::read_to_string(root.join("stderr")).unwrap_or_default()
    );
    let cli = ProcessIdentity::read(probe.leader.pid).expect("refreshed Pyroclast identity");
    assert_eq!(cli.start, probe.leader.start);
    assert_eq!(cli.group, probe.leader.group);
    let cli_args: Vec<_> = cli.command.split(|byte| *byte == 0).collect();
    assert!(
        cli_args
            .iter()
            .any(|arg| { *arg == env!("CARGO_BIN_EXE_pyroclast").as_bytes() })
            && cli_args.iter().any(|arg| *arg == b"memory"),
        "Pyroclast command line was not ready at actor barrier: {}",
        String::from_utf8_lossy(&cli.command)
    );
    probe.leader = cli;

    let actor = actor_identity(&ready_path).expect("actor identity");
    probe.actor = Some(actor.clone());
    assert_ne!(actor.group, probe.leader.group);
    let actor_args: Vec<_> = actor.command.split(|byte| *byte == 0).collect();
    assert!(
        actor_args
            .iter()
            .any(|arg| *arg == actor_exe.as_os_str().as_encoded_bytes())
    );
    assert!(actor_args.iter().any(|arg| *arg == b"heaptrack_actor"));
    assert!(
        wait_until(
            || ProcessIdentity::read(actor.group).is_some_and(|recorder| {
                recorder.parent == probe.leader.pid
                    && recorder.group == recorder.pid
                    && recorder
                        .command
                        .split(|byte| *byte == 0)
                        .any(|argument| argument == heaptrack.as_os_str().as_encoded_bytes())
            }),
            Duration::from_secs(5)
        ),
        "verified heaptrack wrapper did not reach its process group"
    );
    let recorder = ProcessIdentity::read(actor.group).expect("heaptrack process-group leader");
    probe.recorder = Some(recorder.clone());
    assert_eq!(recorder.pid, recorder.group);
    assert_eq!(recorder.parent, probe.leader.pid);
    assert!(recorder.still_matches());
    assert!(
        recorder
            .command
            .split(|byte| *byte == 0)
            .any(|argument| { argument == heaptrack.as_os_str().as_encoded_bytes() }),
        "recorder command line does not identify installed heaptrack: {}",
        String::from_utf8_lossy(&recorder.command)
    );
    probe
}

fn release_actor(root: &Path) {
    std::fs::write(root.join("actor.release"), b"release").expect("release actor barrier");
}

fn wait_for_exit(probe: &Probe, root: &Path) -> i32 {
    assert!(
        wait_until(|| probe.exit_code().is_some(), Duration::from_secs(20)),
        "profile process did not exit; stderr={}",
        std::fs::read_to_string(root.join("stderr")).unwrap_or_default()
    );
    probe.exit_code().unwrap()
}

fn raw_profile(root: &Path) -> PathBuf {
    std::fs::read_dir(root.join("run"))
        .expect("profile output directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.starts_with("profile.raw.heaptrack"))
        })
        .expect("native heaptrack recording")
}

fn native_report(root: &Path, raw: &Path) -> String {
    let print = path_on_path("heaptrack_print");
    let mut command = Command::new(&print);
    command
        .arg(raw)
        .process_group(0)
        .stdout(Stdio::from(
            std::fs::File::create(root.join("heaptrack_print.stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(root.join("heaptrack_print.stderr")).unwrap(),
        ));
    let mut child = ChildGuard::new(command.spawn().expect("run installed heaptrack_print"));
    let pid = i32::try_from(child.child.as_ref().unwrap().id()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut identity = None;
    let status = loop {
        if let Some(status) = child
            .child
            .as_mut()
            .unwrap()
            .try_wait()
            .expect("poll heaptrack_print")
        {
            break status;
        }
        if identity.is_none()
            && let Some(process) = ProcessIdentity::read(pid)
            && process.group == process.pid
            && process
                .command
                .split(|byte| *byte == 0)
                .any(|arg| arg == print.as_os_str().as_encoded_bytes())
        {
            identity = Some(process);
        }
        if Instant::now() >= deadline {
            if let Some(identity) = &identity
                && identity.still_matches()
            {
                // SAFETY: The verified heaptrack_print process owns this group.
                unsafe { libc::kill(-identity.group, libc::SIGKILL) };
            }
            panic!("heaptrack_print exceeded its 15 second deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut finished_child = child.child.take().unwrap();
    assert_eq!(
        finished_child.wait().expect("reap heaptrack_print child"),
        status
    );
    let stdout = std::fs::read(root.join("heaptrack_print.stdout")).unwrap();
    let stderr = std::fs::read_to_string(root.join("heaptrack_print.stderr")).unwrap_or_default();
    assert!(
        status.success(),
        "heaptrack_print failed ({status}): {stderr}"
    );
    let report = String::from_utf8(stdout).expect("heaptrack_print output");
    let totals = parse_heaptrack_summary(&report);
    assert!(totals.total_allocations.unwrap_or_default() > 0, "{report}");
    assert!(totals.peak_heap_bytes.unwrap_or_default() > 0, "{report}");
    report
}

fn assert_no_finalized_summary(root: &Path) {
    assert!(!root.join("run/summary.json").exists());
    assert!(!root.join("run/summary.txt").exists());
    assert!(!root.join("run/run.json").exists());
}

#[test]
fn heaptrack_actor() {
    let Ok(mode) = std::env::var(ACTOR_MODE) else {
        return;
    };
    let mut allocations = Vec::with_capacity(4);
    for byte in 0..4_u8 {
        allocations.push(vec![byte; 2 * 1024 * 1024].into_boxed_slice());
    }
    std::hint::black_box(&allocations);
    let mut signals = (mode == "handled-sigint").then(|| {
        signal_hook::iterator::Signals::new([libc::SIGINT]).expect("install SIGINT handler")
    });
    let ready = PathBuf::from(std::env::var_os(ACTOR_READY).expect("actor ready path"));
    std::fs::write(ready, format!("{}\n", std::process::id())).expect("publish actor identity");

    match mode.as_str() {
        "exit-0" | "exit-130" | "exit-143" => {
            let release =
                PathBuf::from(std::env::var_os(ACTOR_RELEASE).expect("actor release path"));
            assert!(
                wait_until(|| release.is_file(), Duration::from_secs(30)),
                "actor release barrier timed out"
            );
            let status = mode.strip_prefix("exit-").unwrap().parse::<i32>().unwrap();
            std::process::exit(status);
        }
        "handled-sigint" => {
            let signal = signals
                .as_mut()
                .expect("signal handler is installed before readiness")
                .forever()
                .next()
                .expect("actor SIGINT");
            assert_eq!(signal, libc::SIGINT);
            let signal_path = std::env::var_os(ACTOR_SIGNAL).expect("actor signal path");
            std::fs::write(signal_path, signal.to_string()).expect("record delivered SIGINT");
            std::process::exit(130);
        }
        other => panic!("unknown actor mode {other}"),
    }
}

#[test]
fn native_heaptrack_controls_distinguish_deliberate_0_130_and_143_exits() {
    let heaptrack = path_on_path("heaptrack");
    let heaptrack_print = path_on_path("heaptrack_print");
    assert_eq!(heaptrack.parent(), heaptrack_print.parent());

    for (mode, workload_status) in [("exit-0", 0), ("exit-130", 130), ("exit-143", 143)] {
        let root = tempfile::tempdir().unwrap();
        let probe = spawn_profile(root.path(), mode);
        release_actor(root.path());
        let cli_status = wait_for_exit(&probe, root.path());
        let report = native_report(root.path(), &raw_profile(root.path()));
        assert!(report.contains("allocation"), "{report}");

        if workload_status == 0 {
            assert_eq!(cli_status, 0);
            let manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.path().join("run/run.json")).unwrap())
                    .unwrap();
            assert_eq!(manifest["exit_status"], workload_status);
            assert!(root.path().join("run/summary.json").is_file());
        } else {
            assert_eq!(cli_status, 1);
            assert_no_finalized_summary(root.path());
            let error = std::fs::read_to_string(root.path().join("run/tool-errors.log"))
                .expect("backend rejection log");
            assert!(
                error.starts_with(&format!("heaptrack exited with Some({workload_status}):")),
                "{error}"
            );
        }
    }
}

#[test]
fn parent_sigint_with_graceful_actor_exit_130_finalizes_native_heaptrack_data() {
    let root = tempfile::tempdir().unwrap();
    let probe = spawn_profile(root.path(), "handled-sigint");
    assert!(
        probe.leader.signal(libc::SIGINT),
        "verified Pyroclast SIGINT; captured={:?}, current={:?}",
        probe.leader,
        ProcessIdentity::read(probe.leader.pid)
    );
    assert!(
        wait_until(
            || std::fs::read_to_string(root.path().join("actor.signal"))
                .is_ok_and(|signal| signal == "2"),
            Duration::from_secs(5)
        ),
        "allocation actor did not handle forwarded SIGINT"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("actor.signal")).unwrap(),
        "2"
    );

    let cli_status = wait_for_exit(&probe, root.path());
    let raw = raw_profile(root.path());
    let report = native_report(root.path(), &raw);
    assert!(report.contains("allocation"), "{report}");

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("run/run.json")).unwrap()).unwrap();
    assert_eq!(manifest["exit_status"], 130, "raw recorder status changed");
    assert_eq!(cli_status, 130, "parent cancellation CLI status");
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("run/summary.json")).unwrap())
            .unwrap();
    assert!(summary["total_allocations"].as_u64().unwrap_or_default() > 0);
    assert!(summary["peak_heap_bytes"].as_u64().unwrap_or_default() > 0);
    assert!(report.contains("allocation"), "native report lost totals");
}

#[test]
fn actor_only_sigint_with_native_status_130_remains_a_failure() {
    let root = tempfile::tempdir().unwrap();
    let probe = spawn_profile(root.path(), "handled-sigint");
    let actor = probe.actor.as_ref().expect("verified ready actor");
    assert!(actor.signal(libc::SIGINT), "verified actor SIGINT");
    assert!(
        wait_until(
            || std::fs::read_to_string(root.path().join("actor.signal"))
                .is_ok_and(|signal| signal == "2"),
            Duration::from_secs(5)
        ),
        "allocation actor did not handle actor-only SIGINT"
    );
    let cli_status = wait_for_exit(&probe, root.path());
    assert_eq!(
        cli_status, 1,
        "actor-only positive 130 must remain an error"
    );
    let raw = raw_profile(root.path());
    let report = native_report(root.path(), &raw);
    assert!(report.contains("allocation"), "{report}");
    assert_no_finalized_summary(root.path());
    let error = std::fs::read_to_string(root.path().join("run/tool-errors.log")).unwrap();
    assert!(
        error.starts_with("heaptrack exited with Some(130):"),
        "{error}"
    );
}

const PRINT_REPORT: &[u8] = b"total allocations: 42\npeak heap memory consumption: 1024 bytes\n";

#[derive(Clone, Copy)]
enum RawArtifact {
    Valid,
    Missing,
    Truncated,
}

struct PolicyRunner {
    recorder_status: Option<i32>,
    parent_signal: Mutex<Option<i32>>,
    raw: RawArtifact,
    print_status: Option<i32>,
    print_spawn_error: bool,
    recording_calls: AtomicUsize,
    print_calls: AtomicUsize,
    print_purposes: Mutex<Vec<CommandPurpose>>,
    cancellation_reads: AtomicUsize,
    signal_during_print: Option<i32>,
    signal_after_snapshot: Option<i32>,
}

impl PolicyRunner {
    fn new(recorder_status: Option<i32>, parent_signal: Option<i32>) -> Self {
        Self {
            recorder_status,
            parent_signal: Mutex::new(parent_signal),
            raw: RawArtifact::Valid,
            print_status: Some(0),
            print_spawn_error: false,
            recording_calls: AtomicUsize::new(0),
            print_calls: AtomicUsize::new(0),
            print_purposes: Mutex::new(Vec::new()),
            cancellation_reads: AtomicUsize::new(0),
            signal_during_print: None,
            signal_after_snapshot: None,
        }
    }

    fn with_artifact(mut self, raw: RawArtifact, print_status: Option<i32>) -> Self {
        self.raw = raw;
        self.print_status = print_status;
        self
    }
}

impl CommandRunner for PolicyRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        let output = match command.program.as_str() {
            "heaptrack" if command.args == ["--version"] => CommandOutput {
                status_code: Some(0),
                stdout: b"heaptrack policy fixture\n".to_vec(),
                stderr: Vec::new(),
            },
            "heaptrack" => {
                self.recording_calls.fetch_add(1, Ordering::SeqCst);
                if !matches!(self.raw, RawArtifact::Missing) {
                    let path = command
                        .args
                        .windows(2)
                        .find(|args| args[0] == "-o")
                        .unwrap();
                    let bytes = if matches!(self.raw, RawArtifact::Valid) {
                        b"valid native heaptrack data".as_slice()
                    } else {
                        b"truncated".as_slice()
                    };
                    std::fs::write(&path[1], bytes)?;
                }
                CommandOutput {
                    status_code: self.recorder_status,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }
            }
            "heaptrack_print" => {
                self.print_calls.fetch_add(1, Ordering::SeqCst);
                self.print_purposes.lock().unwrap().push(command.purpose);
                if self.print_spawn_error {
                    return Err(std::io::Error::other("fixture print spawn failure"));
                }
                if let Some(signal) = self.signal_during_print {
                    *self.parent_signal.lock().unwrap() = Some(signal);
                }
                let input = command.args.first().expect("raw artifact argument");
                let readable =
                    std::fs::read(input).is_ok_and(|bytes| bytes == b"valid native heaptrack data");
                let status = if readable { self.print_status } else { Some(2) };
                CommandOutput {
                    status_code: status,
                    stdout: if status == Some(0) {
                        PRINT_REPORT.to_vec()
                    } else {
                        Vec::new()
                    },
                    stderr: if readable {
                        b"fixture print failure\n".to_vec()
                    } else {
                        b"invalid or missing raw heaptrack data\n".to_vec()
                    },
                }
            }
            other => panic!("unexpected tool command {other}"),
        };
        Ok(output)
    }

    fn cancellation_signal(&self) -> Option<i32> {
        let reads = self.cancellation_reads.fetch_add(1, Ordering::SeqCst);
        let mut signal = self.parent_signal.lock().unwrap();
        let observed = *signal;
        if reads == 0
            && let Some(later_signal) = self.signal_after_snapshot
        {
            *signal = Some(later_signal);
        }
        observed
    }
}

fn policy_request(out_dir: PathBuf, json: bool) -> ProfileRequest {
    ProfileRequest {
        kind: ProfileKind::Memory,
        command: vec!["test-actor".to_string()],
        out_dir,
        name: None,
        json,
        symbols: false,
        symbolizer: SymbolizerKind::Addr2line,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 1,
        offcpu_method: None,
    }
}

#[test]
fn heaptrack_policy_permits_only_matching_parent_cancel_status_pairs() {
    let cases = [
        (Some(0), None, true),
        (Some(-libc::SIGINT), None, true),
        (Some(-libc::SIGTERM), None, true),
        (Some(130), Some(libc::SIGINT), true),
        (Some(143), Some(libc::SIGTERM), true),
        (Some(130), None, false),
        (Some(143), None, false),
        (Some(143), Some(libc::SIGINT), false),
        (Some(130), Some(libc::SIGTERM), false),
        (Some(42), Some(libc::SIGINT), false),
        (Some(42), Some(libc::SIGTERM), false),
        (Some(137), Some(libc::SIGINT), false),
        (Some(137), Some(libc::SIGTERM), false),
        (Some(-libc::SIGKILL), Some(libc::SIGINT), false),
        (Some(-libc::SIGKILL), Some(libc::SIGTERM), false),
        (Some(137), Some(libc::SIGKILL), false),
        (Some(130), Some(libc::SIGKILL), false),
        (None, Some(libc::SIGINT), false),
    ];

    for json in [false, true] {
        for (recorder_status, parent_signal, succeeds) in cases {
            let root = tempfile::tempdir().unwrap();
            let runner = PolicyRunner::new(recorder_status, parent_signal);
            let result = HeaptrackBackend::new(&runner)
                .profile(&policy_request(root.path().join("profile"), json));
            assert_eq!(
                result.is_ok(),
                succeeds,
                "status={recorder_status:?} parent={parent_signal:?} json={json}"
            );
            assert_eq!(
                runner.cancellation_reads.load(Ordering::SeqCst),
                if succeeds { 2 } else { 1 }
            );
            assert_eq!(runner.recording_calls.load(Ordering::SeqCst), 1);
            if succeeds {
                let result = result.unwrap();
                assert_eq!(result.manifest.exit_status, recorder_status);
                assert_eq!(result.completion.recorder_status, recorder_status);
                assert_eq!(result.completion.cancellation_signal, parent_signal);
                assert_eq!(result.completion.workload, WorkloadOutcome::Unobserved);
                assert_eq!(result.completion.workload.exit_status(), None);
                assert_eq!(result.completion.workload.as_str(), "unobserved");
                let status = recorder_status.unwrap_or(1);
                let expected_cli_status = if status < 0 { 128 - status } else { status };
                assert_eq!(
                    result.completion.exit_code().unwrap(),
                    u8::try_from(expected_cli_status).unwrap()
                );
                assert_eq!(runner.print_calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    *runner.print_purposes.lock().unwrap(),
                    [CommandPurpose::Finalization]
                );
                assert!(result.layout.summary_json().is_file());
            } else {
                assert!(!root.path().join("profile/summary.json").exists());
                assert!(!root.path().join("profile/summary.txt").exists());
                assert!(!root.path().join("profile/run.json").exists());
                assert_eq!(runner.print_calls.load(Ordering::SeqCst), 0);
                let error =
                    std::fs::read_to_string(root.path().join("profile/tool-errors.log")).unwrap();
                assert!(error.starts_with("heaptrack exited with "), "{error}");
            }
        }
    }
}

#[test]
fn heaptrack_policy_requires_readable_raw_data_and_successful_print() {
    for json in [false, true] {
        for (status, signal) in [(130, libc::SIGINT), (143, libc::SIGTERM)] {
            for raw in [
                RawArtifact::Missing,
                RawArtifact::Truncated,
                RawArtifact::Valid,
            ] {
                let root = tempfile::tempdir().unwrap();
                let print_status = if matches!(raw, RawArtifact::Valid) {
                    Some(1)
                } else {
                    Some(0)
                };
                let runner =
                    PolicyRunner::new(Some(status), Some(signal)).with_artifact(raw, print_status);
                let result = HeaptrackBackend::new(&runner)
                    .profile(&policy_request(root.path().join("profile"), json));
                assert!(result.is_err());
                assert_eq!(runner.recording_calls.load(Ordering::SeqCst), 1);
                assert_eq!(runner.print_calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    *runner.print_purposes.lock().unwrap(),
                    [CommandPurpose::Finalization]
                );
                for name in ["summary.json", "summary.txt", "run.json"] {
                    assert!(!root.path().join("profile").join(name).exists(), "{name}");
                }
                let error =
                    std::fs::read_to_string(root.path().join("profile/tool-errors.log")).unwrap();
                assert!(
                    error.starts_with("heaptrack_print exited with Some("),
                    "{error}"
                );
            }
        }
    }
}

#[test]
fn heaptrack_policy_fails_when_print_cannot_spawn() {
    for json in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut runner = PolicyRunner::new(Some(143), Some(libc::SIGTERM));
        runner.print_spawn_error = true;
        assert!(
            HeaptrackBackend::new(&runner)
                .profile(&policy_request(root.path().join("profile"), json))
                .is_err()
        );
        assert_eq!(runner.recording_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.print_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *runner.print_purposes.lock().unwrap(),
            [CommandPurpose::Finalization]
        );
        for name in ["summary.json", "summary.txt", "run.json"] {
            assert!(!root.path().join("profile").join(name).exists(), "{name}");
        }
    }
}

#[test]
fn heaptrack_policy_snapshots_cancellation_before_finalization() {
    let root = tempfile::tempdir().unwrap();
    let mut runner = PolicyRunner::new(Some(130), None);
    runner.signal_after_snapshot = Some(libc::SIGINT);
    assert!(
        HeaptrackBackend::new(&runner)
            .profile(&policy_request(root.path().join("rejected"), true))
            .is_err()
    );
    assert_eq!(runner.cancellation_reads.load(Ordering::SeqCst), 1);
    assert_eq!(runner.print_calls.load(Ordering::SeqCst), 0);
    assert_eq!(*runner.parent_signal.lock().unwrap(), Some(libc::SIGINT));
}

#[test]
fn heaptrack_late_cancellation_updates_completion_not_the_recording_gate() {
    let root = tempfile::tempdir().unwrap();
    let mut runner = PolicyRunner::new(Some(0), None);
    runner.signal_during_print = Some(libc::SIGINT);
    let result = HeaptrackBackend::new(&runner)
        .profile(&policy_request(root.path().join("profile"), false))
        .unwrap();

    assert_eq!(result.manifest.exit_status, Some(0));
    assert_eq!(result.completion.recorder_status, Some(0));
    assert_eq!(result.completion.workload, WorkloadOutcome::Unobserved);
    assert_eq!(result.completion.cancellation_signal, Some(libc::SIGINT));
    assert_eq!(result.completion.exit_code().unwrap(), 130);
    assert_eq!(runner.cancellation_reads.load(Ordering::SeqCst), 2);
    assert_eq!(runner.print_calls.load(Ordering::SeqCst), 1);
}

struct WorkloadCompletionRunner {
    cancellation: Option<i32>,
}

impl CommandRunner for WorkloadCompletionRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        if command.args == ["--version"] {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"bpftrace test fixture\n".to_vec(),
                stderr: Vec::new(),
            });
        }
        let launch = command
            .args
            .windows(2)
            .find(|args| args[0] == "-c")
            .expect("bpftrace workload launcher");
        let child = Command::new("/bin/sh").arg("-c").arg(&launch[1]).output()?;
        let data_path = command
            .args
            .windows(2)
            .find(|args| args[0] == "-o")
            .expect("bpftrace output path")[1]
            .clone();
        std::fs::write(data_path, b"")?;
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: child.stdout,
            stderr: child.stderr,
        })
    }

    fn cancellation_signal(&self) -> Option<i32> {
        self.cancellation
    }
}

#[test]
fn actual_completed_workload_130_and_143_keep_typed_status_with_parent_cause() {
    for (workload_status, parent_signal, expected_cli) in [
        (130, None, 130),
        (143, None, 143),
        (130, Some(libc::SIGTERM), 143),
        (143, Some(libc::SIGINT), 130),
    ] {
        let root = tempfile::tempdir().unwrap();
        let runner = WorkloadCompletionRunner {
            cancellation: parent_signal,
        };
        let request = ProfileRequest {
            kind: ProfileKind::Offcpu,
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("exit {workload_status}"),
            ],
            out_dir: root.path().join("offcpu"),
            name: None,
            json: true,
            symbols: false,
            symbolizer: SymbolizerKind::Addr2line,
            frequency: 997,
            event: PerfEvent::Default,
            call_graph: PerfCallGraph::Fp,
            pid: None,
            tids: Vec::new(),
            threads_of_pid: None,
            duration_secs: 1,
            offcpu_method: Some(OffcpuMethod::Bpftrace),
        };
        let result = OffcpuBackend::new(&runner).profile(&request).unwrap();
        assert_eq!(
            result.completion.workload,
            WorkloadOutcome::Completed(workload_status)
        );
        assert_eq!(result.completion.workload.as_str(), "completed");
        assert_eq!(
            result.completion.workload.exit_status(),
            Some(workload_status)
        );
        assert_eq!(result.completion.recorder_status, Some(0));
        assert_eq!(result.completion.cancellation_signal, parent_signal);
        assert_eq!(
            result.completion.exit_code().unwrap(),
            u8::try_from(expected_cli).unwrap()
        );
        assert_eq!(result.manifest.exit_status, Some(workload_status));
        assert!(
            result
                .manifest
                .diagnostics
                .contains(&"workload outcome: completed".into())
        );
    }
}
