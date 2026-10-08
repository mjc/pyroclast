use std::sync::Mutex;

use crate::tools::{ResolvedTool, ResolverContext, SystemToolResolver, ToolSpec, tool_spec_named};

#[cfg(unix)]
use signal_hook::consts::{SIGINT, SIGTERM};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub stdin: Option<Vec<u8>>,
    pub interactive: bool,
    pub capture_output: bool,
    pub inherit_stderr: bool,
}

impl CommandSpec {
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            stdin: None,
            interactive: false,
            capture_output: false,
            inherit_stderr: false,
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
        run_process(&self.resolved_command(command)?)
    }

    fn resolve_tool(&self, tool: &ToolSpec) -> std::io::Result<ResolvedTool> {
        self.resolver
            .lock()
            .map_err(|_| std::io::Error::other("tool resolver lock poisoned"))?
            .resolve(tool)
    }
}

#[cfg(unix)]
struct InteractiveSignalGuard(Option<signal_hook::SigId>);

#[cfg(unix)]
impl Drop for InteractiveSignalGuard {
    fn drop(&mut self) {
        if let Some(handler) = self.0.take() {
            signal_hook::low_level::unregister(handler);
        }
    }
}

fn run_process(command: &CommandSpec) -> std::io::Result<CommandOutput> {
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
    let mut child = std_command.spawn()?;
    #[cfg(unix)]
    let _sigint_handler = InteractiveSignalGuard(if command.interactive {
        // SAFETY: The handler performs no operations, so it is async-signal-safe.
        // InteractiveSignalGuard unregisters it on every exit path.
        match unsafe { signal_hook::low_level::register(SIGINT, || {}) } {
            Ok(handler) => Some(handler),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    } else {
        None
    });

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
    Ok(CommandOutput {
        status_code: status_code(output.status),
        stdout: output.stdout,
        stderr: output.stderr,
    })
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
