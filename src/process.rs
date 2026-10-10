use std::sync::Mutex;

use crate::tools::{ResolvedTool, ResolverContext, SystemToolResolver, ToolSpec, tool_spec_named};

#[cfg(unix)]
mod cancellation;
#[cfg(unix)]
mod session;
#[cfg(unix)]
pub use cancellation::{CancellationScope, CliWriter};
#[cfg(unix)]
pub use session::CommandSession;
#[cfg(not(unix))]
pub struct CliWriter(bool);

#[cfg(not(unix))]
impl CliWriter {
    /// Creates the stdout writer.
    ///
    /// # Errors
    /// This implementation never fails.
    pub fn stdout() -> std::io::Result<Self> {
        Ok(Self(false))
    }

    /// Creates the stderr writer.
    ///
    /// # Errors
    /// This implementation never fails.
    pub fn stderr() -> std::io::Result<Self> {
        Ok(Self(true))
    }
}

#[cfg(not(unix))]
impl std::io::Write for CliWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0 {
            std::io::stderr().write(bytes)
        } else {
            std::io::stdout().write(bytes)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.0 {
            std::io::stderr().flush()
        } else {
            std::io::stdout().flush()
        }
    }
}
#[cfg(not(unix))]
pub struct CancellationScope;

#[cfg(not(unix))]
impl CancellationScope {
    /// Starts a cancellation scope (Unix signals are unavailable here).
    ///
    /// # Errors
    /// This implementation never fails.
    pub fn enter() -> std::io::Result<Self> {
        Ok(Self)
    }

    #[must_use]
    pub fn exit_code(&self) -> Option<u8> {
        None
    }
}
#[cfg(unix)]
use signal_hook::consts::{SIGINT, SIGTERM};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CommandPurpose {
    #[default]
    Preparation,
    Recording,
    Finalization,
}

impl CommandPurpose {
    fn permits_finalization(self) -> bool {
        match self {
            Self::Recording => false,
            Self::Preparation => FINALIZING.with(|depth| depth.get() != 0),
            Self::Finalization => true,
        }
    }
}

thread_local! {
    static FINALIZING: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Allows explicitly scoped artifact postprocessing and its tool probes after
/// the first cancellation. Recording commands remain forbidden in this scope.
pub struct FinalizationScope(std::marker::PhantomData<std::rc::Rc<()>>);

impl FinalizationScope {
    #[must_use]
    pub fn enter() -> Self {
        FINALIZING.with(|depth| depth.set(depth.get() + 1));
        Self(std::marker::PhantomData)
    }
}

impl Drop for FinalizationScope {
    fn drop(&mut self) {
        FINALIZING.with(|depth| depth.set(depth.get() - 1));
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct InheritedFile {
    name: String,
    file: std::sync::Arc<std::fs::File>,
}

#[cfg(unix)]
impl PartialEq for InheritedFile {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && std::sync::Arc::ptr_eq(&self.file, &other.file)
    }
}

#[cfg(unix)]
impl Eq for InheritedFile {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    #[cfg(unix)]
    pub inherited_files: Vec<InheritedFile>,
    pub stdin: Option<Vec<u8>>,
    pub interactive: bool,
    pub capture_output: bool,
    pub inherit_stderr: bool,
    pub purpose: CommandPurpose,
}

impl CommandSpec {
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            #[cfg(unix)]
            inherited_files: Vec::new(),
            stdin: None,
            interactive: false,
            capture_output: false,
            inherit_stderr: false,
            purpose: CommandPurpose::Preparation,
        }
    }

    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    #[must_use]
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Passes an owned file to the child; the named environment variable holds
    /// its descriptor. Parent descriptors retain their close-on-exec flags.
    #[cfg(unix)]
    #[must_use]
    pub fn inherit_file(
        mut self,
        name: impl Into<String>,
        file: std::sync::Arc<std::fs::File>,
    ) -> Self {
        self.inherited_files.push(InheritedFile {
            name: name.into(),
            file,
        });
        self
    }

    #[must_use]
    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(bytes.into());
        self
    }

    #[must_use]
    pub fn interactive(mut self) -> Self {
        self.interactive = true;
        self
    }

    /// Captures stdout and stderr while retaining interactive stdin and signals.
    #[must_use]
    pub fn capture_output(mut self) -> Self {
        self.capture_output = true;
        self
    }

    #[must_use]
    pub fn inherit_stderr(mut self) -> Self {
        self.inherit_stderr = true;
        self
    }

    #[must_use]
    pub fn recording(mut self) -> Self {
        self.purpose = CommandPurpose::Recording;
        self
    }

    #[must_use]
    pub fn finalization(mut self) -> Self {
        self.purpose = CommandPurpose::Finalization;
        self
    }

    fn permits_finalization(&self) -> bool {
        self.purpose.permits_finalization()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    #[must_use]
    pub fn succeeded_or_interrupted(&self) -> bool {
        self.status_code == Some(0) || status_is_interrupt(self.status_code)
    }
}

pub trait CommandRunner {
    /// Runs a command and captures its exit status and output.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the command cannot be spawned or waited on.
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput>;

    /// Starts an owned request/response child when supported by the runner.
    /// The command must not supply initial stdin or interactive terminal I/O.
    /// Custom runners can return `None` to retain whole-command execution.
    ///
    /// # Errors
    /// Returns an error if the child cannot be prepared or started.
    #[cfg(unix)]
    fn start_session(&self, _command: &CommandSpec) -> std::io::Result<Option<CommandSession>> {
        Ok(None)
    }

    /// First parent cancellation cause, independent of child exit status.
    fn cancellation_signal(&self) -> Option<i32> {
        cancellation_signal()
    }

    /// Resolves a known external tool to a concrete executable path.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when environment probing fails or the tool cannot
    /// be resolved.
    fn resolve_tool(&self, tool: &ToolSpec) -> std::io::Result<ResolvedTool> {
        Ok(ResolvedTool::bare(tool))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RawProcessRunner;

impl CommandRunner for RawProcessRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        run_process(command)
    }
}

pub struct RealCommandRunner {
    resolver: Mutex<SystemToolResolver<RawProcessRunner>>,
}

impl Default for RealCommandRunner {
    fn default() -> Self {
        Self {
            resolver: Mutex::new(SystemToolResolver::new(
                RawProcessRunner,
                ResolverContext::from_env(std::env::consts::OS),
            )),
        }
    }
}

impl RealCommandRunner {
    fn resolved_command(&self, command: &CommandSpec) -> std::io::Result<CommandSpec> {
        let Some(tool) = tool_spec_named(&command.program) else {
            return Ok(command.clone());
        };
        let resolved = self.resolve_tool(&tool)?;
        let mut command = command.clone();
        let existing_args = std::mem::take(&mut command.args);
        command.program = resolved.launch_program;
        command.args = resolved.launch_args;
        command.args.extend(existing_args);
        Ok(command)
    }
}

impl CommandRunner for RealCommandRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        #[cfg(unix)]
        let _scope = CancellationScope::enter()?;
        let _finalization =
            (command.purpose == CommandPurpose::Finalization).then(FinalizationScope::enter);
        check_cancellation(command)?;
        run_process(&self.resolved_command(command)?)
    }

    #[cfg(unix)]
    fn start_session(&self, command: &CommandSpec) -> std::io::Result<Option<CommandSession>> {
        let _scope = CancellationScope::enter()?;
        let _finalization =
            (command.purpose == CommandPurpose::Finalization).then(FinalizationScope::enter);
        check_cancellation(command)?;
        CommandSession::start(&self.resolved_command(command)?).map(Some)
    }

    fn resolve_tool(&self, tool: &ToolSpec) -> std::io::Result<ResolvedTool> {
        self.resolver
            .lock()
            .map_err(|_| std::io::Error::other("tool resolver lock poisoned"))?
            .resolve(tool)
    }
}

#[must_use]
pub fn cancellation_signal() -> Option<i32> {
    #[cfg(unix)]
    return cancellation::signal();
    #[cfg(not(unix))]
    None
}

fn check_cancellation(command: &CommandSpec) -> std::io::Result<()> {
    #[cfg(unix)]
    let repeated = cancellation::repeated();
    #[cfg(not(unix))]
    let repeated = false;
    if cancellation_signal().is_some() && (!command.permits_finalization() || repeated) {
        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "command cancelled before launch",
        ))
    } else {
        Ok(())
    }
}

fn spawn_process(command: &CommandSpec) -> std::io::Result<std::process::Child> {
    check_cancellation(command)?;
    if command.interactive && command.stdin.is_some() {
        return Err(std::io::Error::other(
            "interactive commands cannot also supply piped stdin",
        ));
    }
    let mut std_command = std::process::Command::new(&command.program);
    std_command.args(&command.args);
    if command.interactive {
        std_command.stdin(std::process::Stdio::inherit());
    }
    if command.interactive && !command.capture_output {
        std_command.stdout(std::process::Stdio::inherit());
        std_command.stderr(std::process::Stdio::inherit());
    } else {
        std_command.stdout(std::process::Stdio::piped());
        if command.inherit_stderr {
            std_command.stderr(std::process::Stdio::inherit());
        } else {
            std_command.stderr(std::process::Stdio::piped());
        }
    }
    for (key, value) in &command.env {
        std_command.env(key, value);
    }
    if !command.interactive && command.stdin.is_some() {
        std_command.stdin(std::process::Stdio::piped());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        std_command.process_group(0);
        let inherited_files = configure_inherited_files(&mut std_command, command)?;
        check_cancellation(command)?;
        let child = std_command.spawn()?;
        drop(inherited_files);
        Ok(child)
    }
    #[cfg(not(unix))]
    std_command.spawn()
}

fn run_process(command: &CommandSpec) -> std::io::Result<CommandOutput> {
    #[cfg(unix)]
    let scope = CancellationScope::enter()?;
    let child = spawn_process(command)?;
    #[cfg(unix)]
    return run_owned_process(child, command, &scope);
    #[cfg(not(unix))]
    let mut child = child;
    #[cfg(not(unix))]
    let output = if let Some(bytes) = &command.stdin {
        use std::io::Write;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("failed to open child stdin"))?;
        std::thread::scope(|scope| {
            let writer = scope.spawn(move || match stdin.write_all(bytes) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                Err(error) => Err(error),
            });
            let output = child.wait_with_output();
            writer
                .join()
                .map_err(|_| std::io::Error::other("child stdin writer panicked"))??;
            output
        })?
    } else if command.interactive && !command.capture_output {
        let status = child.wait();
        let status = status?;
        std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    } else {
        child.wait_with_output()?
    };
    #[cfg(not(unix))]
    Ok(CommandOutput {
        status_code: status_code(output.status),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[cfg(unix)]
fn configure_inherited_files(
    child: &mut std::process::Command,
    command: &CommandSpec,
) -> std::io::Result<Vec<std::os::fd::OwnedFd>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;

    let mut files = Vec::with_capacity(command.inherited_files.len());
    for inherited in &command.inherited_files {
        // Allocate before fork, above stdio and without choosing a fixed FD
        // that might collide with Rust's exec-error pipe. Parent FDs stay CLOEXEC.
        let fd = unsafe { libc::fcntl(inherited.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { OwnedFd::from_raw_fd(fd) };
        child.env(&inherited.name, fd.to_string());
        files.push(file);
    }
    if !files.is_empty() {
        let descriptors = files.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        // The child only calls async-signal-safe fcntl; allocations and
        // environment construction are complete before fork.
        unsafe {
            child.pre_exec(move || {
                for fd in &descriptors {
                    let flags = libc::fcntl(*fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    Ok(files)
}

#[cfg(unix)]
struct OwnedProcess {
    child: std::process::Child,
    group: i32,
    reaped: bool,
}

#[cfg(unix)]
impl OwnedProcess {
    fn signal(&self, signal: i32) {
        self.signal_with(signal, |target, signal| {
            // SAFETY: signal_with selects only the pinned child/original group.
            unsafe { libc::kill(target, signal) }
        });
    }

    fn signal_with(&self, signal: i32, mut send: impl FnMut(i32, i32) -> i32) {
        // The unreaped child pins its PID and original group ID. Group delivery
        // already includes an in-group leader; a second send can run its handler
        // twice. Never signal the leader's destination group.
        send(-self.group, signal);
        // SAFETY: The child remains unreaped, so getpgid cannot inspect a reused PID.
        let leader_group = unsafe { libc::getpgid(self.group) };
        if leader_group != self.group || signal == libc::SIGKILL {
            // Always kill the pinned leader before waiting: it can change groups
            // between the group send and membership check. SIGKILL has no handler.
            send(self.group, signal);
        }
    }

    fn completed(&self) -> std::io::Result<bool> {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: info is writable and this runner owns the unreaped child.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error);
        }
        // SAFETY: Successful waitid initialized info; si_pid is zero when
        // WNOHANG found no completed child. WNOWAIT preserves leader identity.
        Ok(unsafe { info.assume_init().si_pid() } != 0)
    }
}

#[cfg(unix)]
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.reaped {
            self.signal(libc::SIGKILL);
            let _ = self.child.wait();
        }
    }
}

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fd belongs to a live owned pipe; fcntl does not retain it.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn drain_pipe<P: std::io::Read>(pipe: &mut Option<P>, bytes: &mut Vec<u8>) -> std::io::Result<()> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    let mut buffer = [0; 8192];
    // Limit each turn so a continuously writing child cannot starve signals
    // or the other pipe.
    for _ in 0..8 {
        match reader.read(&mut buffer) {
            Ok(0) => {
                *pipe = None;
                break;
            }
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn run_owned_process(
    child: std::process::Child,
    command: &CommandSpec,
    scope: &CancellationScope,
) -> std::io::Result<CommandOutput> {
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    let group = i32::try_from(child.id()).map_err(std::io::Error::other)?;
    let mut owned = OwnedProcess {
        child,
        group,
        reaped: false,
    };
    let mut terminal = if command.interactive {
        cancellation::TerminalForeground::handoff(group)?
    } else {
        None
    };
    if terminal.is_some() {
        // A child that read stdin before handoff may have received SIGTTIN.
        owned.signal(libc::SIGCONT);
    }
    let mut stdout = owned.child.stdout.take();
    let mut stderr = owned.child.stderr.take();
    let mut stdin = owned.child.stdin.take();
    if let Some(pipe) = &stdout {
        nonblocking(pipe)?;
    }
    if let Some(pipe) = &stderr {
        nonblocking(pipe)?;
    }
    if let Some(pipe) = &stdin {
        nonblocking(pipe)?;
    }
    let input = command.stdin.as_deref().unwrap_or_default();
    let mut written = 0;
    let mut output = CommandOutput {
        status_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let mut stopping = None;
    let mut terminated = false;
    let mut killed = None;
    let mut forwarded = false;
    let finalizing_after_cancellation = command.permits_finalization() && scope.signal().is_some();
    let mut leader_completed = false;
    loop {
        let now = Instant::now();
        if let Some(signal) = scope.signal()
            && !forwarded
            && (!finalizing_after_cancellation || scope.repeated())
        {
            owned.signal(signal);
            owned.signal(libc::SIGCONT);
            forwarded = true;
            // perf's tools/perf/builtin-record.c:record__finish_output can outlive this deadline.
            // A repeated stop still takes the immediate SIGKILL path below.
            if command.purpose != CommandPurpose::Recording {
                stopping = Some(now + Duration::from_millis(350));
            }
            stdin = None;
        }
        if !leader_completed {
            leader_completed = owned.completed()?;
        }
        if stopping.is_none() && leader_completed {
            stopping = Some(now + Duration::from_millis(50));
            stdin = None;
        }
        if killed.is_none() && scope.repeated() {
            owned.signal(libc::SIGKILL);
            killed = Some(now);
        } else if stopping.is_some_and(|deadline| now >= deadline) && killed.is_none() {
            if terminated {
                owned.signal(libc::SIGKILL);
                killed = Some(now);
            } else {
                owned.signal(libc::SIGTERM);
                terminated = true;
                stopping = Some(now + Duration::from_millis(if forwarded { 350 } else { 50 }));
            }
        }
        drain_pipe(&mut stdout, &mut output.stdout)?;
        drain_pipe(&mut stderr, &mut output.stderr)?;
        write_child_stdin(&mut stdin, input, &mut written)?;
        if (leader_completed && stdout.is_none() && stderr.is_none())
            || killed.is_some_and(|at| {
                (stdout.is_none() && stderr.is_none()) || at.elapsed() >= Duration::from_millis(100)
            })
        {
            // Close even pipes held by descendants that escaped the group.
            // No blocking reader/writer threads survive this boundary.
            drop(stdout);
            drop(stderr);
            drop(stdin);
            // Even the EOF fast path cleans the group before releasing its
            // leader identity. Do not wait for zombie-only groups to vanish.
            owned.signal(libc::SIGKILL);
            if let Some(terminal) = &mut terminal {
                terminal.restore()?;
            }
            output.status_code = status_code(owned.child.wait()?);
            owned.reaped = true;
            return Ok(output);
        }
        poll_child_pipes([
            stdout.as_ref().map(AsRawFd::as_raw_fd),
            stderr.as_ref().map(AsRawFd::as_raw_fd),
            stdin.as_ref().map(AsRawFd::as_raw_fd),
        ])?;
    }
}

#[cfg(unix)]
fn write_child_stdin(
    stdin: &mut Option<std::process::ChildStdin>,
    input: &[u8],
    written: &mut usize,
) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(pipe) = stdin.as_mut() {
        let end = input.len().min(*written + 65536);
        match pipe.write(&input[*written..end]) {
            Ok(count) => *written += count,
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => *stdin = None,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        if *written == input.len() {
            *stdin = None;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn poll_child_pipes(fds: [Option<std::os::fd::RawFd>; 3]) -> std::io::Result<()> {
    let mut descriptors = [libc::pollfd {
        fd: -1,
        events: libc::POLLIN,
        revents: 0,
    }; 3];
    for (descriptor, fd) in descriptors.iter_mut().zip(fds) {
        descriptor.fd = fd.unwrap_or(-1);
    }
    descriptors[2].events = libc::POLLOUT;
    let count = descriptors
        .len()
        .try_into()
        .expect("three pipe descriptors fit poll's descriptor count");
    // SAFETY: poll borrows the initialized descriptors for this call only.
    // The short timeout bounds response latency for atomic-only handlers.
    let result = unsafe { libc::poll(descriptors.as_mut_ptr(), count, 20) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn status_code(status: std::process::ExitStatus) -> Option<i32> {
    status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
}

#[cfg(not(unix))]
fn status_code(status: std::process::ExitStatus) -> Option<i32> {
    status.code()
}

#[cfg(unix)]
fn status_is_interrupt(status_code: Option<i32>) -> bool {
    matches!(status_code, Some(code) if code == -SIGINT || code == -SIGTERM)
}

#[cfg(not(unix))]
fn status_is_interrupt(_status_code: Option<i32>) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::{OwnedProcess, nonblocking, poll_child_pipes};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{ChildStdout, Command, Stdio};
    use std::time::{Duration, Instant};

    fn recorder_ack(stdout: &mut ChildStdout) -> u8 {
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut byte = [0];
        loop {
            match stdout.read(&mut byte) {
                Ok(1) => return byte[0],
                Ok(_) => panic!("recorder closed its acknowledgment pipe"),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("recorder acknowledgment failed: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "recorder acknowledgment timed out"
            );
            poll_child_pipes([Some(stdout.as_raw_fd()), None, None]).unwrap();
        }
    }

    #[test]
    fn owned_group_sigint_reaches_leader_once() {
        // A shell trap can be deferred until its builtin read finishes. A
        // native async-signal-safe acknowledgment measures delivery itself.
        let root = tempfile::tempdir().unwrap();
        let recorder = root.path().join("signal-recorder");
        let output = Command::new("cc")
            .args([
                "-std=c11",
                "-D_POSIX_C_SOURCE=200809L",
                "-Wall",
                "-Wextra",
                "-Werror",
            ])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/signal_recorder.c"
            ))
            .arg("-o")
            .arg(&recorder)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut command = Command::new(recorder);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        // SAFETY: The hook uses only async-signal-safe operations on local data.
        // Nextest may ignore or block SIGINT; the recorder must be able to trap it.
        unsafe {
            command.pre_exec(|| {
                if libc::signal(libc::SIGINT, libc::SIG_DFL) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
                let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
                if libc::sigemptyset(mask.as_mut_ptr()) < 0
                    || libc::sigaddset(mask.as_mut_ptr(), libc::SIGINT) < 0
                    || libc::sigprocmask(libc::SIG_UNBLOCK, mask.as_ptr(), std::ptr::null_mut()) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let group = i32::try_from(child.id()).unwrap();
        let mut owned = OwnedProcess {
            child,
            group,
            reaped: false,
        };
        let mut stdout = owned.child.stdout.take().unwrap();
        nonblocking(&stdout).unwrap();
        assert_eq!(recorder_ack(&mut stdout), b'R');
        let mut targets = Vec::new();
        owned.signal_with(libc::SIGINT, |target, signal| {
            targets.push(target);
            // SAFETY: The child remains unreaped, pinning both test-owned IDs.
            let result = unsafe { libc::kill(target, signal) };
            assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
            // Ack before allowing another send: pending standard signals
            // cannot coalesce and hide a duplicate production delivery.
            assert_eq!(recorder_ack(&mut stdout), b'I');
            result
        });
        assert_eq!(
            targets,
            [-group],
            "one cancellation reached the leader twice"
        );
    }
}
