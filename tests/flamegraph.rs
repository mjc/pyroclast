use pyroclast::flamegraph::{FlamegraphRenderer, FlamegraphRequest, InfernoFlamegraphRenderer};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

#[test]
fn inferno_renderer_rejects_nonzero_exit_status() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = FailingRunner;
    let renderer = InfernoFlamegraphRenderer::new(&runner);

    let error = renderer
        .render(&FlamegraphRequest {
            title: "CPU profile".to_string(),
            folded_stacks: "app;work 1\n".to_string(),
            output: root.path().join("flamegraph.svg"),
        })
        .expect_err("nonzero inferno should fail");

    assert!(
        error
            .to_string()
            .contains("inferno-flamegraph exited with Some(42)")
    );
    assert!(error.to_string().contains("bad folded stack"));
    assert!(!root.path().join("flamegraph.svg").exists());
}

struct FailingRunner;

impl CommandRunner for FailingRunner {
    fn run(&self, _command: &CommandSpec) -> std::io::Result<CommandOutput> {
        Ok(CommandOutput {
            status_code: Some(42),
            stdout: b"<svg>partial</svg>\n".to_vec(),
            stderr: b"bad folded stack".to_vec(),
        })
    }
}
