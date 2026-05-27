use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};
use pyroclast::tools::{
    ResolverContext, SystemToolResolver, ToolKind, ToolSource, ToolSpec, collect_tool_versions,
    required_tools, tool_spec_named,
};

#[test]
fn linux_required_tools_include_nix_managed_profilers() {
    let tools = required_tools("linux");
    let names: Vec<_> = tools.iter().map(|tool| tool.name).collect();

    assert!(names.contains(&"perf"));
    assert!(names.contains(&"inferno-collapse-perf"));
    assert!(names.contains(&"inferno-flamegraph"));
    assert!(names.contains(&"addr2line"));
    assert!(names.contains(&"heaptrack"));
    assert!(names.contains(&"heaptrack_print"));
    assert!(names.contains(&"strace"));
    assert!(names.contains(&"bpftrace"));
    assert!(names.contains(&"valgrind"));
    assert!(names.contains(&"tokio-console"));
    assert!(tools.iter().all(|tool| tool.kind == ToolKind::NixManaged));
}

#[test]
fn macos_required_tools_mark_xctrace_as_apple_provided() {
    let tools = required_tools("macos");
    let xctrace = tools
        .iter()
        .find(|tool| tool.name == "xctrace")
        .expect("xctrace tool");

    assert_eq!(xctrace.kind, ToolKind::AppleProvided);
    assert!(tools.iter().any(|tool| tool.name == "inferno-flamegraph"));
    assert!(tools.iter().any(|tool| tool.name == "tokio-console"));
}

#[test]
fn collects_tool_versions_with_version_flag() {
    let runner = VersionRunner;
    let versions = collect_tool_versions(&runner, &[ToolSpec::nix_managed("perf")]);

    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].name, "perf");
    assert_eq!(versions[0].path.as_deref(), Some("perf"));
    assert_eq!(versions[0].source, Some(ToolSource::Path));
    assert_eq!(versions[0].version.as_deref(), Some("perf version 6.9"));
    assert_eq!(versions[0].error, None);
}

#[test]
fn resolver_prefers_supported_path_tools() {
    let root = tempfile::tempdir().expect("tempdir");
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&bin).expect("bin dir");
    std::fs::write(bin.join("perf"), b"").expect("perf stub");
    std::fs::write(bin.join("nix"), b"").expect("nix stub");
    let path = std::env::join_paths([bin.as_path()]).expect("join path");
    let mut resolver = SystemToolResolver::new(
        VersionRunner,
        ResolverContext::for_tests("linux", root.path(), Some(path), false),
    );

    let tool_path = resolver
        .resolve(&tool_spec_named("perf").expect("perf tool"))
        .expect("resolve perf");

    assert_eq!(tool_path.path, bin.join("perf").display().to_string());
    assert_eq!(tool_path.source, ToolSource::Path);
    assert_eq!(tool_path.version.as_deref(), Some("perf version 6.9"));
}

#[test]
fn resolver_uses_project_flake_for_missing_safe_utility() {
    let root = tempfile::tempdir().expect("tempdir");
    let project = root.path().join("project/subdir");
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&project).expect("project dir");
    std::fs::create_dir_all(&bin).expect("bin dir");
    std::fs::write(root.path().join("project/flake.nix"), b"{}").expect("flake");
    std::fs::write(bin.join("nix"), b"").expect("nix stub");
    let path = std::env::join_paths([bin.as_path()]).expect("join path");
    let runner = NixFallbackRunner::default();
    let mut resolver = SystemToolResolver::new(
        &runner,
        ResolverContext::for_tests("linux", &project, Some(path), false),
    );

    let tool_path = resolver
        .resolve(&tool_spec_named("inferno-flamegraph").expect("inferno-flamegraph"))
        .expect("resolve inferno-flamegraph");

    assert_eq!(tool_path.source, ToolSource::ProjectFlake);
    assert_eq!(
        tool_path.path,
        "/nix/store/fake/bin/inferno-flamegraph".to_string()
    );
    assert!(runner.saw_develop());
}

#[test]
fn resolver_rejects_xctrace_wrapper_stub() {
    let root = tempfile::tempdir().expect("tempdir");
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&bin).expect("bin dir");
    std::fs::write(bin.join("xctrace"), b"").expect("xctrace stub");
    let path = std::env::join_paths([bin.as_path()]).expect("join path");
    let mut resolver = SystemToolResolver::new(
        XctraceWrapperRunner,
        ResolverContext::for_tests("macos", root.path(), Some(path), false),
    );

    let error = resolver
        .resolve(&tool_spec_named("xctrace").expect("xctrace"))
        .expect_err("wrapper should fail");

    assert!(error.to_string().contains("Xcode"));
}

#[test]
fn resolver_uses_ephemeral_nix_for_safe_utility_without_flake() {
    let root = tempfile::tempdir().expect("tempdir");
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&bin).expect("bin dir");
    std::fs::write(bin.join("nix"), b"").expect("nix stub");
    let path = std::env::join_paths([bin.as_path()]).expect("join path");
    let runner = NixFallbackRunner::default();
    let mut resolver = SystemToolResolver::new(
        &runner,
        ResolverContext::for_tests("linux", root.path(), Some(path), false),
    );

    let tool_path = resolver
        .resolve(&tool_spec_named("inferno-collapse-perf").expect("inferno-collapse-perf"))
        .expect("resolve inferno-collapse-perf");

    assert_eq!(tool_path.source, ToolSource::EphemeralNix);
    assert_eq!(
        tool_path.path,
        "/nix/store/fake/bin/inferno-collapse-perf".to_string()
    );
    assert!(runner.saw_shell());
}

#[test]
fn resolver_does_not_use_ephemeral_nix_for_perf() {
    let root = tempfile::tempdir().expect("tempdir");
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&bin).expect("bin dir");
    std::fs::write(bin.join("nix"), b"").expect("nix stub");
    let path = std::env::join_paths([bin.as_path()]).expect("join path");
    let runner = NixFallbackRunner::default();
    let mut resolver = SystemToolResolver::new(
        &runner,
        ResolverContext::for_tests("linux", root.path(), Some(path), false),
    );

    let error = resolver
        .resolve(&tool_spec_named("perf").expect("perf"))
        .expect_err("perf should not use ephemeral nix");

    assert!(error.to_string().contains("perf"));
    assert_eq!(runner.commands_len(), 0);
}

#[test]
fn resolver_caches_project_flake_probes() {
    let root = tempfile::tempdir().expect("tempdir");
    let project = root.path().join("project/subdir");
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&project).expect("project dir");
    std::fs::create_dir_all(&bin).expect("bin dir");
    std::fs::write(root.path().join("project/flake.nix"), b"{}").expect("flake");
    std::fs::write(bin.join("nix"), b"").expect("nix stub");
    let path = std::env::join_paths([bin.as_path()]).expect("join path");
    let runner = NixFallbackRunner::default();
    let mut resolver = SystemToolResolver::new(
        &runner,
        ResolverContext::for_tests("linux", &project, Some(path), false),
    );
    let tool = tool_spec_named("inferno-flamegraph").expect("inferno-flamegraph");

    let first = resolver.resolve(&tool).expect("first resolve");
    let second = resolver.resolve(&tool).expect("second resolve");

    assert_eq!(first, second);
    assert_eq!(runner.matching_commands("develop"), 1);
    assert_eq!(
        runner.matching_program("/nix/store/fake/bin/inferno-flamegraph"),
        1
    );
}

struct VersionRunner;

impl CommandRunner for VersionRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        assert_eq!(
            std::path::Path::new(&command.program)
                .file_name()
                .and_then(std::ffi::OsStr::to_str),
            Some("perf")
        );
        assert_eq!(command.args, ["--version"]);
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"perf version 6.9\nextra\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}

#[derive(Default)]
struct NixFallbackRunner {
    commands: std::sync::Mutex<Vec<CommandSpec>>,
}

impl NixFallbackRunner {
    fn saw_develop(&self) -> bool {
        self.matching_commands("develop") > 0
    }

    fn saw_shell(&self) -> bool {
        self.matching_commands("shell") > 0
    }

    fn commands_len(&self) -> usize {
        self.commands.lock().unwrap().len()
    }

    fn matching_commands(&self, needle: &str) -> usize {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|command| {
                command.program.ends_with("/nix") && command.args.iter().any(|arg| arg == needle)
            })
            .count()
    }

    fn matching_program(&self, program: &str) -> usize {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|command| command.program == program)
            .count()
    }
}

fn nix_resolution_output(path: &str) -> CommandOutput {
    CommandOutput {
        status_code: Some(0),
        stdout: format!("{path}\n").into_bytes(),
        stderr: Vec::new(),
    }
}

impl CommandRunner for &NixFallbackRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if command.program.ends_with("/nix") && command.args.iter().any(|arg| arg == "develop") {
            return Ok(nix_resolution_output(
                "/nix/store/fake/bin/inferno-flamegraph",
            ));
        }
        if command.program.ends_with("/nix") && command.args.iter().any(|arg| arg == "shell") {
            return Ok(nix_resolution_output(
                "/nix/store/fake/bin/inferno-collapse-perf",
            ));
        }
        if command.program == "/nix/store/fake/bin/inferno-flamegraph"
            && command.args == ["--version"]
        {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"inferno-flamegraph 0.12.6\n".to_vec(),
                stderr: Vec::new(),
            });
        }
        if command.program == "/nix/store/fake/bin/inferno-collapse-perf"
            && command.args == ["--version"]
        {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"inferno-collapse-perf 0.12.6\n".to_vec(),
                stderr: Vec::new(),
            });
        }
        panic!("unexpected command: {command:?}");
    }
}

struct XctraceWrapperRunner;

impl CommandRunner for XctraceWrapperRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        assert!(command.program.ends_with("/xctrace"));
        assert_eq!(command.args, ["--version"]);
        Ok(CommandOutput {
            status_code: Some(1),
            stdout: Vec::new(),
            stderr: b"xctrace requires Xcode".to_vec(),
        })
    }
}
