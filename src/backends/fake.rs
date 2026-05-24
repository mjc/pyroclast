use std::fs;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::ArtifactLayout;
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::manifest::{BackendName, RunManifest};

#[derive(Default)]
pub struct FakeBackend;

impl ProfilerBackend for FakeBackend {
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult> {
        let layout = ArtifactLayout::new(request.out_dir.clone());
        fs::create_dir_all(layout.root())?;

        write_file(layout.stdout_log(), "")?;
        write_file(layout.stderr_log(), "")?;
        write_file(layout.command_txt(), request.command.join(" "))?;
        write_file(layout.summary_txt(), "fake profile complete\n")?;
        write_file(layout.summary_json(), "{}\n")?;
        write_file(layout.tool_errors_log(), "")?;

        let manifest = RunManifest {
            command: request.command.clone(),
            cwd: std::env::current_dir()?,
            profile_kind: request.kind,
            requested_backend: BackendName::Fake,
            actual_backend: BackendName::Fake,
            fallback_reason: None,
            platform: std::env::consts::OS.to_string(),
            started_at_unix_ms: unix_ms_now(),
            ended_at_unix_ms: Some(unix_ms_now()),
            exit_status: Some(0),
            artifacts: vec![
                layout.run_json(),
                layout.stdout_log(),
                layout.stderr_log(),
                layout.command_txt(),
                layout.summary_txt(),
                layout.summary_json(),
                layout.tool_errors_log(),
            ],
            diagnostics: vec!["fake backend used".to_string()],
        };

        write_file(layout.run_json(), serde_json::to_string_pretty(&manifest)?)?;

        Ok(ProfileResult { layout, manifest })
    }
}

fn write_file(path: std::path::PathBuf, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(contents.as_ref())
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
