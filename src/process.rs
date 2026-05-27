use std::sync::Mutex;

use crate::tools::{ResolvedTool, ResolverContext, SystemToolResolver, ToolSpec, tool_spec_named};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub stdin: Option<Vec<u8>>,
    pub interactive: bool,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
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
        command.program = resolved.path;
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
        std_command.stdout(std::process::Stdio::inherit());
        std_command.stderr(std::process::Stdio::inherit());
    } else {
        std_command.stdout(std::process::Stdio::piped());
        std_command.stderr(std::process::Stdio::piped());
    }
    for (key, value) in &command.env {
        std_command.env(key, value);
    }
    if !command.interactive && command.stdin.is_some() {
        std_command.stdin(std::process::Stdio::piped());
    }
    let mut child = std_command.spawn()?;
    if let Some(stdin) = &command.stdin {
        use std::io::Write;

        match child
            .stdin
            .as_mut()
            .ok_or_else(|| std::io::Error::other("failed to open child stdin"))?
            .write_all(stdin)
        {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => return Err(error),
        }
    }
    let output = if command.interactive {
        let status = child.wait()?;
        std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    } else {
        child.wait_with_output()?
    };
    Ok(CommandOutput {
        status_code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}
