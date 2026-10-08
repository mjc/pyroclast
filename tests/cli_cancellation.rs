#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct ProcessIdentity {
    pid: i32,
    start: String,
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
            group: fields.get(2)?.parse().ok()?,
            command: std::fs::read(format!("/proc/{pid}/cmdline")).ok()?,
        })
    }

    fn alive(&self) -> bool {
        Self::read(self.pid).is_some_and(|current| current.start == self.start)
            && std::fs::read_to_string(format!("/proc/{}/stat", self.pid))
                .ok()
                .and_then(|stat| {
                    stat.rsplit_once(") ")
                        .map(|(_, tail)| tail.starts_with('Z'))
                })
                == Some(false)
    }

    fn signal(&self, signal: i32) -> bool {
        if Self::read(self.pid)
            .is_some_and(|current| current.start == self.start && current.command == self.command)
        {
            // SAFETY: This is the verified process created by this test.
            unsafe { libc::kill(self.pid, signal) == 0 }
        } else {
            false
        }
    }
}

struct Probe {
    child: Child,
    leader: ProcessIdentity,
    owned: Vec<ProcessIdentity>,
}

impl Probe {
    fn exited(&self) -> bool {
        self.exit_code().is_some()
    }

    fn exit_code(&self) -> Option<i32> {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // Observe without reaping so the leader pins its PID/group for cleanup.
        // SAFETY: info is writable; this test owns the child being observed.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        // SAFETY: Successful waitid initialized info, including a zero PID
        // when no child state change is available.
        let info = unsafe { info.assume_init() };
        // SAFETY: waitid sets these fields for a reported child transition.
        if unsafe { info.si_pid() } == 0 {
            None
        } else {
            // SAFETY: A nonzero child PID indicates initialized status fields.
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
        for process in &self.owned {
            if process.group == process.pid
                && ProcessIdentity::read(process.pid)
                    .is_some_and(|current| current.start == process.start)
            {
                // SAFETY: This is the verified test-created recorder group.
                unsafe { libc::kill(-process.group, libc::SIGKILL) };
            }
            let _ = process.signal(libc::SIGKILL);
        }
        if ProcessIdentity::read(self.leader.pid)
            .is_some_and(|current| current.start == self.leader.start)
        {
            // SAFETY: Our unreaped CLI child pins the test-owned group ID.
            unsafe { libc::kill(-self.leader.group, libc::SIGKILL) };
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn executable(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn wait_until(mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !predicate() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

fn read_identity(path: &Path) -> Option<ProcessIdentity> {
    ProcessIdentity::read(std::fs::read_to_string(path).ok()?.trim().parse().ok()?)
}

fn launch(root: &Path, stubborn: bool) -> (Probe, PathBuf) {
    let tools = root.join("bin");
    std::fs::create_dir(&tools).unwrap();
    executable(
        &tools.join("bpftrace"),
        r#"#!/bin/sh
if [ "$1" = --version ]; then echo 'bpftrace v0.26.0'; exit 0; fi
while [ $# -gt 0 ]; do
    case "$1" in -c) shift; workload=$1;; -o) shift; data=$1;; esac
    shift
done
finish() {
    trap '' INT TERM
    kill -TERM "$supervisor" 2>/dev/null
    wait "$supervisor"
    printf '@offcpu[\n    1 wait+0 ([kernel.kallsyms])\n]: 200\n' > "$data"
    exit 0
}
if [ "$PYROCLAST_TEST_STUBBORN" = yes ]; then trap '' INT TERM; else trap finish INT TERM; fi
/bin/sh -c "$workload" &
supervisor=$!
printf '%s\n' "$$" > "$PYROCLAST_TEST_RECORDER_PID"
printf '%s\n' "$supervisor" > "$PYROCLAST_TEST_SUPERVISOR_PID"
wait "$supervisor"
finish
"#,
    );
    let out = root.join("run");
    let child = Command::new(env!("CARGO_BIN_EXE_pyroclast"))
        .args(["offcpu", "--offcpu-method", "bpftrace", "--json", "--out"])
        .arg(&out)
        .args(["--", "/bin/sh", "-c"])
        .arg("printf '%s\n' \"$$\" > \"$PYROCLAST_TEST_WORKLOAD_PID\"; exec sleep 30")
        .env(
            "PATH",
            format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
        )
        .env("PYROCLAST_TEST_RECORDER_PID", root.join("recorder.pid"))
        .env("PYROCLAST_TEST_SUPERVISOR_PID", root.join("supervisor.pid"))
        .env("PYROCLAST_TEST_WORKLOAD_PID", root.join("workload.pid"))
        .env(
            "PYROCLAST_TEST_STUBBORN",
            if stubborn { "yes" } else { "no" },
        )
        .stdout(Stdio::from(
            std::fs::File::create(root.join("stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(root.join("stderr")).unwrap(),
        ))
        .process_group(0)
        .spawn()
        .unwrap();
    let leader = ProcessIdentity::read(i32::try_from(child.id()).unwrap()).unwrap();
    let mut probe = Probe {
        child,
        leader,
        owned: Vec::new(),
    };
    for name in ["recorder", "supervisor", "workload"] {
        let path = root.join(format!("{name}.pid"));
        assert!(
            wait_until(|| read_identity(&path).is_some(), Duration::from_secs(5)),
            "{name} never became ready: {}",
            std::fs::read_to_string(root.join("stderr")).unwrap()
        );
        probe.owned.push(read_identity(&path).unwrap());
    }
    let ready = ProcessIdentity::read(probe.leader.pid).unwrap();
    assert_eq!(ready.start, probe.leader.start);
    probe.leader = ready;
    (probe, out)
}

fn check_direct_cancellation(signal: i32, stubborn: bool) {
    let root = tempfile::tempdir().unwrap();
    let (probe, out) = launch(root.path(), stubborn);
    assert!(
        probe.leader.signal(signal),
        "verified CLI PID must receive the cancellation signal"
    );
    let exited = wait_until(|| probe.exited(), Duration::from_secs(4));
    let survivors: Vec<_> = probe
        .owned
        .iter()
        .filter(|process| process.alive())
        .map(|process| process.pid)
        .collect();
    assert!(
        exited,
        "CLI ignored direct signal {signal}; survivors={survivors:?}"
    );
    assert!(
        survivors.is_empty(),
        "CLI exited without stopping owned processes: {survivors:?}"
    );
    assert_eq!(probe.exit_code(), Some(128 + signal));
    if !stubborn {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("run.json")).unwrap()).unwrap();
        assert!(
            manifest["exit_status"].is_null(),
            "cancellation must not invent workload success"
        );
        let summary: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["workload_outcome"], "interrupted");
    }
}

#[test]
fn direct_cli_sigint_stops_and_reaps_owned_recorder_and_workload() {
    check_direct_cancellation(libc::SIGINT, false);
}

#[test]
fn direct_cli_sigterm_stops_and_reaps_owned_recorder_and_workload() {
    check_direct_cancellation(libc::SIGTERM, false);
}

#[test]
fn direct_cli_sigint_escalates_when_recorder_ignores_signals() {
    check_direct_cancellation(libc::SIGINT, true);
}

#[test]
fn direct_cli_sigterm_escalates_when_recorder_ignores_signals() {
    check_direct_cancellation(libc::SIGTERM, true);
}

fn launch_fixture(root: &Path, script: &str) -> Probe {
    let tools = root.join("bin");
    std::fs::create_dir(&tools).unwrap();
    executable(&tools.join("bpftrace"), script);
    let child = Command::new(env!("CARGO_BIN_EXE_pyroclast"))
        .args(["offcpu", "--offcpu-method", "bpftrace", "--json", "--out"])
        .arg(root.join("run"))
        .args([
            "--",
            "sh",
            "-c",
            "printf launched > \"$PYROCLAST_TEST_LAUNCHED\"",
        ])
        .env(
            "PATH",
            format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
        )
        .env("PYROCLAST_TEST_READY", root.join("ready.pid"))
        .env("PYROCLAST_TEST_LAUNCHED", root.join("launched"))
        .stdout(Stdio::from(
            std::fs::File::create(root.join("stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(root.join("stderr")).unwrap(),
        ))
        .process_group(0)
        .spawn()
        .unwrap();
    let leader = ProcessIdentity::read(i32::try_from(child.id()).unwrap()).unwrap();
    let mut probe = Probe {
        child,
        leader,
        owned: Vec::new(),
    };
    let path = root.join("ready.pid");
    assert!(wait_until(
        || read_identity(&path).is_some(),
        Duration::from_secs(5)
    ));
    probe.owned.push(read_identity(&path).unwrap());
    let ready = ProcessIdentity::read(probe.leader.pid).unwrap();
    assert_eq!(ready.start, probe.leader.start);
    probe.leader = ready;
    probe
}

#[test]
fn cancellation_during_tool_preflight_stops_probe_without_launching_workload() {
    let root = tempfile::tempdir().unwrap();
    let probe = launch_fixture(
        root.path(),
        r#"#!/bin/sh
if [ "$1" = --version ]; then
    printf '%s\n' "$$" > "$PYROCLAST_TEST_READY"
    exec sleep 30
fi
printf launched > "$PYROCLAST_TEST_LAUNCHED"
exit 0
"#,
    );
    assert!(probe.leader.signal(libc::SIGTERM));
    assert!(
        wait_until(|| probe.exited(), Duration::from_secs(4)),
        "preflight cancellation hung"
    );
    assert_eq!(probe.exit_code(), Some(128 + libc::SIGTERM));
    assert!(probe.owned.iter().all(|process| !process.alive()));
    assert!(
        !root.path().join("launched").exists(),
        "cancelled preflight launched work"
    );
}

#[test]
fn recorder_completion_with_descendant_held_pipes_does_not_hang_cli() {
    let root = tempfile::tempdir().unwrap();
    let probe = launch_fixture(
        root.path(),
        r#"#!/bin/sh
if [ "$1" = --version ]; then echo 'bpftrace v0.26.0'; exit 0; fi
while [ $# -gt 0 ]; do
    case "$1" in -c) shift; workload=$1;; -o) shift; data=$1;; esac
    shift
done
/bin/sh -c "$workload"
(trap '' INT TERM; exec sleep 30) &
printf '%s\n' "$!" > "$PYROCLAST_TEST_READY"
printf '@offcpu[\n    1 wait+0 ([kernel.kallsyms])\n]: 200\n' > "$data"
exit 0
"#,
    );
    assert!(
        wait_until(|| probe.exited(), Duration::from_secs(4)),
        "descendant-held pipes blocked completion"
    );
    assert_eq!(probe.exit_code(), Some(0));
    assert!(
        probe.owned.iter().all(|process| !process.alive()),
        "pipe holder survived cleanup"
    );
}

#[test]
fn repeated_signal_escalates_without_overwriting_first_cancellation_cause() {
    let root = tempfile::tempdir().unwrap();
    let (probe, _) = launch(root.path(), true);
    assert!(probe.leader.signal(libc::SIGINT));
    // The first handler is installed before readiness. Give its publication
    // a turn before sending a different escalation signal.
    std::thread::sleep(Duration::from_millis(50));
    assert!(probe.leader.signal(libc::SIGTERM));
    assert!(wait_until(|| probe.exited(), Duration::from_secs(4)));
    assert_eq!(probe.exit_code(), Some(128 + libc::SIGINT));
    assert!(probe.owned.iter().all(|process| !process.alive()));
}

#[test]
fn cancellation_unblocks_final_cli_stdout_write() {
    use std::os::fd::AsRawFd;

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("summary.txt"), vec![b'x'; 4 * 1024 * 1024]).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_pyroclast"))
        .args(["plumbing", "summarize"])
        .arg(root.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            std::fs::File::create(root.path().join("stderr")).unwrap(),
        ))
        .process_group(0)
        .spawn()
        .unwrap();
    let leader = ProcessIdentity::read(i32::try_from(child.id()).unwrap()).unwrap();
    let mut probe = Probe {
        child,
        leader,
        owned: Vec::new(),
    };
    let mut descriptor = libc::pollfd {
        fd: probe.child.stdout.as_ref().unwrap().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor refers to our live child's stdout pipe. Do not drain
    // it: this test must cancel while the final writer cannot make progress.
    assert_eq!(unsafe { libc::poll(&raw mut descriptor, 1, 5000) }, 1);
    assert_ne!(descriptor.revents & libc::POLLIN, 0);
    std::thread::sleep(Duration::from_millis(50));
    assert!(!probe.exited());
    let ready = ProcessIdentity::read(probe.leader.pid).unwrap();
    assert_eq!(ready.start, probe.leader.start);
    probe.leader = ready;
    assert!(probe.leader.signal(libc::SIGTERM));
    assert!(
        wait_until(|| probe.exited(), Duration::from_secs(4)),
        "final stdout writer ignored cancellation"
    );
    assert_eq!(probe.exit_code(), Some(128 + libc::SIGTERM));
}

fn pty_command(command: &mut Command) -> std::fs::File {
    use std::os::fd::FromRawFd;

    let mut master = -1;
    let mut slave = -1;
    // SAFETY: openpty initializes both descriptors; null termios/winsize
    // selects terminal defaults. Both descriptors immediately gain owners.
    assert_eq!(
        unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: Successful openpty returned distinct owned descriptors.
    let master = unsafe { std::fs::File::from_raw_fd(master) };
    // SAFETY: slave is the other descriptor returned by openpty.
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    command.stdin(Stdio::from(slave));
    // SAFETY: This pre-exec hook uses only async-signal-safe session/terminal
    // operations, after std::process has installed the slave as fd 0.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::tcsetpgrp(0, libc::getpgrp()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    master
}

fn launch_pty(root: &Path) -> (Probe, std::fs::File) {
    let tools = root.join("bin");
    std::fs::create_dir(&tools).unwrap();
    executable(
        &tools.join("bpftrace"),
        r#"#!/bin/sh
if [ "$1" = --version ]; then echo 'bpftrace v0.26.0'; exit 0; fi
while [ $# -gt 0 ]; do
    case "$1" in -c) shift; workload=$1;; -o) shift; data=$1;; esac
    shift
done
finish() {
    trap '' INT TERM
    kill -TERM "$supervisor" 2>/dev/null
    wait "$supervisor"
    printf '@offcpu[\n    1 wait+0 ([kernel.kallsyms])\n]: 200\n' > "$data"
    exit 0
}
trap finish INT TERM
printf '%s\n' "$$" > "$PYROCLAST_TEST_READY"
read -r line
printf '%s\n' "$line" > "$PYROCLAST_TEST_INPUT"
/bin/sh -c "$workload" &
supervisor=$!
wait "$supervisor"
finish
"#,
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_pyroclast"));
    command
        .args(["offcpu", "--offcpu-method", "bpftrace", "--json", "--out"])
        .arg(root.join("run"))
        .args([
            "--",
            "sh",
            "-c",
            "printf '%s\\n' \"$$\" > \"$PYROCLAST_TEST_WORKLOAD\"; exec sleep 30",
        ])
        .env(
            "PATH",
            format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
        )
        .env("PYROCLAST_TEST_READY", root.join("ready.pid"))
        .env("PYROCLAST_TEST_INPUT", root.join("input"))
        .env("PYROCLAST_TEST_WORKLOAD", root.join("workload.pid"))
        .stdout(Stdio::from(
            std::fs::File::create(root.join("stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(root.join("stderr")).unwrap(),
        ));
    let master = pty_command(&mut command);
    let child = command.spawn().unwrap();
    let leader = ProcessIdentity::read(i32::try_from(child.id()).unwrap()).unwrap();
    let mut probe = Probe {
        child,
        leader,
        owned: Vec::new(),
    };
    let path = root.join("ready.pid");
    assert!(wait_until(
        || read_identity(&path).is_some(),
        Duration::from_secs(5)
    ));
    probe.owned.push(read_identity(&path).unwrap());
    let ready = ProcessIdentity::read(probe.leader.pid).unwrap();
    assert_eq!(ready.start, probe.leader.start);
    probe.leader = ready;
    (probe, master)
}

fn check_pty_cancellation(direct: bool) {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let root = tempfile::tempdir().unwrap();
    let (mut probe, mut master) = launch_pty(root.path());
    // SAFETY: master is the live test-owned PTY paired with the CLI's stdin.
    let foreground = unsafe { libc::tcgetpgrp(master.as_raw_fd()) };
    assert_eq!(
        foreground, probe.owned[0].group,
        "interactive recorder did not receive terminal foreground"
    );
    master.write_all(b"terminal input\n").unwrap();
    let path = root.path().join("workload.pid");
    assert!(
        wait_until(|| read_identity(&path).is_some(), Duration::from_secs(5)),
        "interactive stdin did not reach recorder"
    );
    assert_eq!(
        std::fs::read(root.path().join("input")).unwrap(),
        b"terminal input\n"
    );
    probe.owned.push(read_identity(&path).unwrap());
    if direct {
        assert!(probe.leader.signal(libc::SIGTERM));
    } else {
        // Terminal-generated Ctrl-C targets the foreground recorder group,
        // not the CLI PID. This deliberately differs from the direct tests.
        master.write_all(&[3]).unwrap();
    }
    assert!(
        wait_until(|| probe.exited(), Duration::from_secs(4)),
        "PTY cancellation hung"
    );
    assert_eq!(probe.exit_code(), Some(if direct { 143 } else { 130 }));
    assert!(probe.owned.iter().all(|process| !process.alive()));
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("run/summary.json")).unwrap())
            .unwrap();
    assert_eq!(summary["workload_outcome"], "interrupted");
}

#[test]
fn pty_ctrl_c_cancels_foreground_recorder_independently_of_cli_pid_signals() {
    check_pty_cancellation(false);
}

#[test]
fn direct_cli_cancellation_also_stops_recorder_owning_terminal_foreground() {
    check_pty_cancellation(true);
}

fn tracked_child(child: Child) -> Probe {
    let leader = ProcessIdentity::read(i32::try_from(child.id()).unwrap()).unwrap();
    Probe {
        child,
        leader,
        owned: Vec::new(),
    }
}

fn launch_runner_probe(root: &Path, mode: &str, terminal: bool) -> (Probe, Option<std::fs::File>) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "cancellation_runner_probe", "--nocapture"])
        .env("PYROCLAST_TEST_RUNNER_MODE", mode)
        .env("PYROCLAST_TEST_RUNNER_ROOT", root)
        .stdout(Stdio::from(
            std::fs::File::create(root.join("stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(root.join("stderr")).unwrap(),
        ));
    let master = if terminal {
        Some(pty_command(&mut command))
    } else {
        command.process_group(0);
        None
    };
    (tracked_child(command.spawn().unwrap()), master)
}

fn assert_probe_success(probe: &Probe, root: &Path) {
    assert!(
        wait_until(|| probe.exited(), Duration::from_secs(4)),
        "runner probe hung: {}",
        std::fs::read_to_string(root.join("stderr")).unwrap()
    );
    assert_eq!(
        probe.exit_code(),
        Some(0),
        "runner probe failed:\n{}\n{}",
        std::fs::read_to_string(root.join("stdout")).unwrap(),
        std::fs::read_to_string(root.join("stderr")).unwrap()
    );
}

fn set_terminal_foreground(group: i32) {
    let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: Initialize the mask, block SIGTTOU only on this helper thread,
    // change its owned PTY, then restore the successfully initialized mask.
    unsafe {
        assert_eq!(libc::sigemptyset(mask.as_mut_ptr()), 0);
        assert_eq!(libc::sigaddset(mask.as_mut_ptr(), libc::SIGTTOU), 0);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, mask.as_ptr(), previous.as_mut_ptr()),
            0
        );
        let result = libc::tcsetpgrp(0, group);
        let error = std::io::Error::last_os_error();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, previous.as_ptr(), std::ptr::null_mut()),
            0
        );
        assert_eq!(result, 0, "{error}");
    }
}

fn terminal_modes() -> libc::termios {
    let mut modes = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: fd 0 is the helper's live PTY; tcgetattr initializes modes.
    assert_eq!(unsafe { libc::tcgetattr(0, modes.as_mut_ptr()) }, 0);
    // SAFETY: The successful query initialized the termios structure.
    unsafe { modes.assume_init() }
}

fn run_terminal_probe(
    mode: &str,
    root: &Path,
    runner: &pyroclast::process::RealCommandRunner,
    scope: &pyroclast::process::CancellationScope,
) {
    use pyroclast::process::{CommandRunner, CommandSpec};

    // SAFETY: Queries only; this helper owns the controlling PTY.
    let original_group = unsafe { libc::getpgrp() };
    // SAFETY: fd 0 is the controlling PTY installed by pty_command.
    assert_eq!(unsafe { libc::tcgetpgrp(0) }, original_group);
    let original_modes = terminal_modes();
    let peer = (mode == "nonowned_terminal").then(|| {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let peer = tracked_child(child);
        set_terminal_foreground(peer.leader.group);
        std::fs::write(root.join("peer.pid"), peer.leader.pid.to_string()).unwrap();
        peer
    });
    let script = if peer.is_some() {
        "printf '%s\\n' \"$$\" > \"$PYROCLAST_TEST_READY\"; exec sleep 30"
    } else {
        "stty -echo -icanon; printf '%s\\n' \"$$\" > \"$PYROCLAST_TEST_READY\"; exec sleep 30"
    };
    let output = runner
        .run(
            &CommandSpec::new("sh")
                .args(["-c", script])
                .env(
                    "PYROCLAST_TEST_READY",
                    root.join("ready.pid").to_str().unwrap(),
                )
                .interactive()
                .capture_output(),
        )
        .unwrap();
    assert_eq!(scope.signal(), Some(libc::SIGTERM));
    assert_eq!(output.status_code, Some(-libc::SIGTERM));
    let expected_group = peer
        .as_ref()
        .map_or(original_group, |peer| peer.leader.group);
    // SAFETY: Observe restoration before the session leader exits.
    assert_eq!(unsafe { libc::tcgetpgrp(0) }, expected_group);
    if peer.is_none() {
        let restored = terminal_modes();
        assert_eq!(restored.c_iflag, original_modes.c_iflag);
        assert_eq!(restored.c_oflag, original_modes.c_oflag);
        assert_eq!(restored.c_cflag, original_modes.c_cflag);
        assert_eq!(
            restored.c_lflag, original_modes.c_lflag,
            "cancelled workload left terminal modes changed"
        );
        assert_eq!(restored.c_cc, original_modes.c_cc);
    }
    set_terminal_foreground(original_group);
    drop(peer);
}

// Signal and controlling-terminal state must be exercised in an isolated
// process, not in the integration-test harness shared with unrelated tests.
#[test]
fn cancellation_runner_probe() {
    use pyroclast::process::{
        CancellationScope, CommandRunner, CommandSpec, FinalizationScope, RealCommandRunner,
    };

    let Ok(mode) = std::env::var("PYROCLAST_TEST_RUNNER_MODE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("PYROCLAST_TEST_RUNNER_ROOT").unwrap());
    let scope = CancellationScope::enter().unwrap();
    let runner = RealCommandRunner::default();
    match mode.as_str() {
        "terminal_modes" | "nonowned_terminal" => {
            run_terminal_probe(&mode, &root, &runner, &scope);
        }
        "moved_leader" => {
            let group = std::fs::read_to_string(root.join("destination.group")).unwrap();
            let output = runner
                .run(
                    &CommandSpec::new(std::env::current_exe().unwrap().to_str().unwrap())
                        .args(["--exact", "moved_process_actor", "--nocapture"])
                        .env("PYROCLAST_TEST_MOVE_GROUP", group)
                        .env("PYROCLAST_TEST_RUNNER_ROOT", root.to_str().unwrap())
                        .recording(),
                )
                .unwrap();
            assert_eq!(scope.signal(), Some(libc::SIGTERM));
            assert_eq!(output.status_code, Some(-libc::SIGTERM));
        }
        "held_pipes" | "cancel_held_pipes" => {
            let output = runner
                .run(&CommandSpec::new("sh")
                    .args(["-c", r#"
exec 3<&0
setsid sh -c 'trap "" INT TERM; printf "%s\n" "$$" > "$PYROCLAST_TEST_HOLDER"; exec sleep 30' <&3 3<&- >/dev/null &
exec 3<&-
printf '%s\n' "$$" > "$PYROCLAST_TEST_READY"
while [ ! -e "$PYROCLAST_TEST_RELEASE" ]; do sleep 0.01; done
exit 7
"#])
                    .env("PYROCLAST_TEST_READY", root.join("ready.pid").to_str().unwrap())
                    .env("PYROCLAST_TEST_HOLDER", root.join("holder.pid").to_str().unwrap())
                    .env("PYROCLAST_TEST_RELEASE", root.join("release").to_str().unwrap())
                    .stdin(vec![b'x'; 4 * 1024 * 1024]))
                .unwrap();
            if mode == "held_pipes" {
                assert_eq!(output.status_code, Some(7));
                assert_eq!(scope.signal(), None);
            } else {
                assert_eq!(scope.signal(), Some(libc::SIGTERM));
                assert_eq!(output.status_code, Some(-libc::SIGTERM));
            }
        }
        "finalization" => {
            // SAFETY: This isolated helper installed its cancellation scope.
            assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            let command = CommandSpec::new("sh").args(["-c", "printf finalized"]);
            assert_eq!(
                runner.run(&command).unwrap_err().kind(),
                std::io::ErrorKind::Interrupted
            );
            assert_eq!(
                runner.run(&command.clone().finalization()).unwrap().stdout,
                b"finalized"
            );
            {
                let _finalization = FinalizationScope::enter();
                assert_eq!(runner.run(&command).unwrap().stdout, b"finalized");
                assert_eq!(
                    runner.run(&command.clone().recording()).unwrap_err().kind(),
                    std::io::ErrorKind::Interrupted
                );
            }
            assert_eq!(
                runner.run(&command).unwrap_err().kind(),
                std::io::ErrorKind::Interrupted
            );
            // SAFETY: A second signal belongs only to this helper's scope.
            assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
            assert_eq!(scope.signal(), Some(libc::SIGTERM));
            assert_eq!(
                runner.run(&command.finalization()).unwrap_err().kind(),
                std::io::ErrorKind::Interrupted
            );
        }
        _ => panic!("unknown runner probe: {mode}"),
    }
}

fn check_runner_terminal(mode: &str) {
    use std::os::fd::AsRawFd;

    let root = tempfile::tempdir().unwrap();
    let (mut probe, master) = launch_runner_probe(root.path(), mode, true);
    let master = master.unwrap();
    assert!(wait_until(
        || read_identity(&root.path().join("ready.pid")).is_some(),
        Duration::from_secs(5)
    ));
    probe
        .owned
        .push(read_identity(&root.path().join("ready.pid")).unwrap());
    let expected = if mode == "nonowned_terminal" {
        let peer = read_identity(&root.path().join("peer.pid")).unwrap();
        let group = peer.group;
        probe.owned.push(peer);
        group
    } else {
        probe.owned[0].group
    };
    // SAFETY: master is the live PTY belonging to our helper's session.
    assert_eq!(unsafe { libc::tcgetpgrp(master.as_raw_fd()) }, expected);
    probe.leader = ProcessIdentity::read(probe.leader.pid).unwrap();
    assert!(probe.leader.signal(libc::SIGTERM));
    assert_probe_success(&probe, root.path());
}

#[test]
fn pty_cancellation_restores_foreground_and_terminal_modes_before_returning() {
    check_runner_terminal("terminal_modes");
}

#[test]
fn cancellation_does_not_take_or_restore_another_groups_terminal_foreground() {
    check_runner_terminal("nonowned_terminal");
}

fn check_escaped_pipe_holder(cancel: bool) {
    let root = tempfile::tempdir().unwrap();
    let mode = if cancel {
        "cancel_held_pipes"
    } else {
        "held_pipes"
    };
    let (mut probe, _) = launch_runner_probe(root.path(), mode, false);
    for name in ["ready", "holder"] {
        let path = root.path().join(format!("{name}.pid"));
        assert!(wait_until(
            || read_identity(&path).is_some(),
            Duration::from_secs(5)
        ));
        probe.owned.push(read_identity(&path).unwrap());
    }
    assert_ne!(
        probe.owned[0].group, probe.owned[1].group,
        "pipe holder must escape the runner's owned group"
    );
    assert_eq!(
        std::fs::read_link(format!("/proc/{}/fd/0", probe.owned[0].pid)).unwrap(),
        std::fs::read_link(format!("/proc/{}/fd/0", probe.owned[1].pid)).unwrap(),
        "escaped holder must retain the configured stdin pipe"
    );
    if cancel {
        probe.leader = ProcessIdentity::read(probe.leader.pid).unwrap();
        assert!(probe.leader.signal(libc::SIGTERM));
    } else {
        std::fs::write(root.path().join("release"), b"exit").unwrap();
    }
    assert_probe_success(&probe, root.path());
    assert!(
        !probe.owned[0].alive(),
        "owned leader survived runner cleanup"
    );
    assert!(
        probe.owned[1].alive(),
        "runner must close escaped pipes without signaling a non-owned group"
    );
}

#[test]
fn runner_completion_is_bounded_with_escaped_stdin_and_stderr_pipe_holder() {
    check_escaped_pipe_holder(false);
}

#[test]
fn runner_cancellation_is_bounded_with_escaped_stdin_and_stderr_pipe_holder() {
    check_escaped_pipe_holder(true);
}

#[test]
fn finalization_permission_does_not_allow_recording_or_survive_second_signal() {
    let root = tempfile::tempdir().unwrap();
    let (probe, _) = launch_runner_probe(root.path(), "finalization", false);
    assert_probe_success(&probe, root.path());
}

fn full_stdout_pipe(command: &mut Command) -> std::fs::File {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};

    let mut descriptors = [-1; 2];
    // SAFETY: pipe2 initializes two new descriptors, immediately given owners.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    // SAFETY: These distinct descriptors were returned by successful pipe2.
    let reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
    // SAFETY: The write descriptor has not otherwise been given an owner.
    let mut writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
    loop {
        match writer.write(&[b'x'; 4096]) {
            Ok(count) => assert!(count > 0),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill output pipe: {error}"),
        }
    }
    // SAFETY: The writer is live; make the child's inherited stdout blocking.
    let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    // SAFETY: The same live descriptor's previous flags were just queried.
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) },
        0
    );
    command.stdout(Stdio::from(writer));
    reader
}

fn stdout_writer_waiting(pid: i32) -> bool {
    // Accept either blocking writes or cancellation-aware polling, so the
    // readiness check remains valid after the parser's output path is fixed.
    std::fs::read_to_string(format!("/proc/{pid}/wchan")).is_ok_and(|state| {
        state.contains("pipe_write")
            || state.contains("poll_schedule_timeout")
            || state.contains("do_poll")
    })
}

fn check_blocked_help(cargo: bool) {
    let root = tempfile::tempdir().unwrap();
    let mut command = Command::new(if cargo {
        env!("CARGO_BIN_EXE_cargo-pyroclast")
    } else {
        env!("CARGO_BIN_EXE_pyroclast")
    });
    if cargo {
        command.arg("pyroclast");
    }
    command
        .arg("--help")
        .stderr(Stdio::from(
            std::fs::File::create(root.path().join("stderr")).unwrap(),
        ))
        .process_group(0);
    let _reader = full_stdout_pipe(&mut command);
    let mut probe = tracked_child(command.spawn().unwrap());
    assert!(
        wait_until(
            || stdout_writer_waiting(probe.leader.pid),
            Duration::from_secs(5)
        ),
        "CLI never reached its blocked help output"
    );
    probe.leader = ProcessIdentity::read(probe.leader.pid).unwrap();
    assert!(probe.leader.signal(libc::SIGTERM));
    assert!(
        wait_until(|| probe.exited(), Duration::from_secs(4)),
        "help output ignored cancellation on a full stdout pipe"
    );
    assert_eq!(probe.exit_code(), Some(143));
}

#[test]
fn cancellation_unblocks_direct_cli_help_stdout_write() {
    check_blocked_help(false);
}

#[test]
fn cancellation_unblocks_cargo_cli_help_stdout_write() {
    check_blocked_help(true);
}

#[test]
fn cancellation_unblocks_cargo_cli_final_stdout_write() {
    let root = tempfile::tempdir().unwrap();
    let tools = root.path().join("bin");
    std::fs::create_dir(&tools).unwrap();
    executable(
        &tools.join("cargo"),
        "#!/bin/sh\ncat \"$PYROCLAST_TEST_CARGO_ARTIFACT\"\n",
    );
    executable(
        &tools.join("bpftrace"),
        r#"#!/bin/sh
if [ "$1" = --version ]; then echo 'bpftrace v0.26.0'; exit 0; fi
while [ $# -gt 0 ]; do
    case "$1" in -c) shift; workload=$1;; -o) shift; data=$1;; esac
    shift
done
/bin/sh -c "$workload"
printf '@offcpu[\n    1 wait+0 ([kernel.kallsyms])\n]: 200\n' > "$data"
exit 0
"#,
    );
    let artifact = root.path().join("cargo-artifact.json");
    std::fs::write(
        &artifact,
        serde_json::to_vec(&serde_json::json!({
            "reason": "compiler-artifact", "package_id": "path+file:///fixture#fixture@0.1.0",
            "manifest_path": "/fixture/Cargo.toml",
            "target": {
                "name": "fixture", "kind": ["bin"], "crate_types": ["bin"],
                "src_path": "/fixture/src/main.rs", "edition": "2024",
                "doc": true, "doctest": false, "test": true,
            },
            "profile": {
                "opt_level": "0", "debuginfo": 2, "debug_assertions": false,
                "overflow_checks": true, "test": false,
            },
            "features": [], "filenames": [], "executable": "/bin/sh", "fresh": true,
        }))
        .unwrap(),
    )
    .unwrap();
    let out = root.path().join("run");
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-pyroclast"));
    command
        .args([
            "pyroclast",
            "offcpu",
            "--bin",
            "fixture",
            "--offcpu-method",
            "bpftrace",
            "--json",
            "--out",
        ])
        .arg(&out)
        .args(["--", "-c", "exit 0"])
        .env(
            "PATH",
            format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
        )
        .env("PYROCLAST_TEST_CARGO_ARTIFACT", artifact)
        .stderr(Stdio::from(
            std::fs::File::create(root.path().join("stderr")).unwrap(),
        ))
        .process_group(0);
    let _reader = full_stdout_pipe(&mut command);
    let mut probe = tracked_child(command.spawn().unwrap());
    assert!(
        wait_until(
            || out.join("run.json").exists() && stdout_writer_waiting(probe.leader.pid),
            Duration::from_secs(5)
        ),
        "Cargo CLI never reached its blocked final output: {}",
        std::fs::read_to_string(root.path().join("stderr")).unwrap()
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("run.json")).unwrap()).unwrap();
    assert_eq!(manifest["exit_status"], 0);
    assert!(
        !probe.exited(),
        "prefilled stdout pipe must block final output"
    );
    probe.leader = ProcessIdentity::read(probe.leader.pid).unwrap();
    assert!(probe.leader.signal(libc::SIGTERM));
    assert!(
        wait_until(|| probe.exited(), Duration::from_secs(4)),
        "Cargo CLI final stdout writer ignored cancellation"
    );
    assert_eq!(probe.exit_code(), Some(143));
}

#[test]
fn moved_process_actor() {
    let Ok(group) = std::env::var("PYROCLAST_TEST_MOVE_GROUP") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("PYROCLAST_TEST_RUNNER_ROOT").unwrap());
    let group: i32 = group.parse().unwrap();
    // SAFETY: This isolated helper joins the test-owned peer's existing group
    // in the same session. It installs no cancellation handlers of its own.
    assert_eq!(unsafe { libc::setpgid(0, group) }, 0);
    std::fs::write(root.join("moved.pid"), std::process::id().to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

struct MovedLeaderGuard {
    runner: Probe,
    moved: Option<ProcessIdentity>,
    root: PathBuf,
}

impl Drop for MovedLeaderGuard {
    fn drop(&mut self) {
        if let Some(moved) = self
            .moved
            .clone()
            .or_else(|| read_identity(&self.root.join("moved.pid")))
        {
            // signal rechecks both start time and the full command. Never
            // signal the destination group: its peer is not runner-owned.
            let _ = moved.signal(libc::SIGKILL);
        }
        // Killing the moved child releases the runner's wait so it can reap
        // that child before we reap the runner. Bound cleanup on the RED path.
        if !wait_until(|| self.runner.exited(), Duration::from_secs(4)) {
            let _ = self.runner.leader.signal(libc::SIGKILL);
            let _ = wait_until(|| self.runner.exited(), Duration::from_secs(4));
        }
    }
}

#[test]
fn runner_cancellation_reaps_leader_that_joins_another_process_group() {
    let root = tempfile::tempdir().unwrap();
    let peer = tracked_child(
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    std::fs::write(
        root.path().join("destination.group"),
        peer.leader.group.to_string(),
    )
    .unwrap();
    let (runner, _) = launch_runner_probe(root.path(), "moved_leader", false);
    let mut guard = MovedLeaderGuard {
        runner,
        moved: None,
        root: root.path().to_path_buf(),
    };
    assert!(wait_until(
        || read_identity(&root.path().join("moved.pid")).is_some(),
        Duration::from_secs(5)
    ));
    let moved = read_identity(&root.path().join("moved.pid")).unwrap();
    assert_eq!(moved.group, peer.leader.group);
    assert_ne!(
        moved.group, moved.pid,
        "owned leader must leave its initial group"
    );
    guard.moved = Some(moved.clone());
    guard.runner.leader = ProcessIdentity::read(guard.runner.leader.pid).unwrap();
    assert!(guard.runner.leader.signal(libc::SIGTERM));
    assert!(
        wait_until(|| guard.runner.exited(), Duration::from_secs(4)),
        "runner hung waiting for an owned leader that moved groups"
    );
    assert_probe_success(&guard.runner, root.path());
    assert!(
        peer.leader.alive(),
        "cancellation signaled a non-owned peer group"
    );
    assert!(
        ProcessIdentity::read(moved.pid).is_none(),
        "owned moved child was not reaped"
    );
}

#[test]
fn recorder_sigterm_without_workload_completion_returns_143_without_parent_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let probe = launch_fixture(
        root.path(),
        r#"#!/bin/sh
if [ "$1" = --version ]; then echo 'bpftrace v0.26.0'; exit 0; fi
while [ $# -gt 0 ]; do
    case "$1" in -o) shift; data=$1;; esac
    shift
done
printf '@offcpu[\n    1 wait+0 ([kernel.kallsyms])\n]: 200\n' > "$data"
printf '%s\n' "$$" > "$PYROCLAST_TEST_READY"
while [ ! -e "$PYROCLAST_TEST_READY.release" ]; do sleep 0.01; done
kill -TERM "$$"
"#,
    );
    std::fs::write(root.path().join("ready.pid.release"), b"stop recorder").unwrap();
    assert!(wait_until(|| probe.exited(), Duration::from_secs(4)));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("run/run.json")).unwrap()).unwrap();
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("run/summary.json")).unwrap())
            .unwrap();
    let emitted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("stdout")).unwrap()).unwrap();
    assert!(manifest["exit_status"].is_null());
    assert!(emitted["exit_status"].is_null());
    assert!(summary["cancellation_signal"].is_null());
    assert_eq!(summary["recorder_status"], -libc::SIGTERM);
    assert_eq!(summary["workload_outcome"], "interrupted");
    assert_eq!(summary["total_offcpu_ns"], 200);
    assert_eq!(probe.exit_code(), Some(143));
}
