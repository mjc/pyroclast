use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
struct Args {
    /// Already-built shipping binary; never built by this runner.
    #[arg(long)]
    pyroclast: PathBuf,
    #[arg(long)]
    matrix: PathBuf,
    /// Must not exist, so stale artifacts cannot satisfy checks.
    #[arg(long)]
    out: PathBuf,
    /// GNU time (also available in the repository's Darwin devenv).
    #[arg(long, default_value = "time")]
    time: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    repetitions: usize,
    rows: Vec<Row>,
    comparisons: Vec<Comparison>,
    #[serde(default)]
    inputs: Vec<PathBuf>,
    /// Explicit cache, affinity, load, settings and workflow-scope declarations.
    #[serde(default)]
    conditions: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    name: String,
    stages: Vec<Stage>,
    #[serde(default)]
    required_artifacts: Vec<PathBuf>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    name: String,
    argv: Vec<String>,
    #[serde(default)]
    stdin: Option<PathBuf>,
    #[serde(default)]
    stdout: Option<PathBuf>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Comparison {
    left: PathBuf,
    right: PathBuf,
}

#[derive(Debug, Serialize)]
struct Observation {
    repetition: usize,
    row: String,
    wall_seconds: f64,
    complete: bool,
    stages: Vec<StageObservation>,
    comparisons: Vec<ComparisonObservation>,
    artifact_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct StageObservation {
    name: String,
    argv: Vec<String>,
    wall_seconds: f64,
    wrapper_exit_code: Option<i32>,
    wrapper_signal: Option<i32>,
    error: Option<String>,
    resources: Option<Resources>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Resources {
    user_seconds: f64,
    system_seconds: f64,
    max_rss_kib: u64,
    termination: String,
    target_exit_code: String,
    target_signal: String,
}

#[derive(Debug, Serialize)]
struct ComparisonObservation {
    left: PathBuf,
    right: PathBuf,
    matches: bool,
    error: Option<String>,
}

fn safe_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.starts_with(".measurement")
        && path
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
}

fn validate(matrix: &Matrix) -> Result<(), String> {
    if matrix.repetitions == 0 || matrix.rows.is_empty() {
        return Err("repetitions and rows must be nonempty".into());
    }
    let mut names = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    for row in &matrix.rows {
        if !valid_name(&row.name) || !names.insert(&row.name) || row.stages.is_empty() {
            return Err("rows require unique safe names and nonempty stages".into());
        }
        if row.required_artifacts.iter().any(|path| !safe_path(path)) {
            return Err("required artifacts must be relative paths".into());
        }
        let mut stages = BTreeSet::new();
        for stage in &row.stages {
            if !valid_name(&stage.name)
                || !stages.insert(&stage.name)
                || stage.argv.first().is_none_or(String::is_empty)
                || stage.argv.iter().any(|arg| arg.contains('\0'))
                || stage
                    .stdin
                    .iter()
                    .chain(&stage.stdout)
                    .any(|path| !safe_path(path))
            {
                return Err(
                    "stages require unique safe names, argv and relative artifact paths".into(),
                );
            }
            if stage
                .stdout
                .as_ref()
                .is_some_and(|path| !outputs.insert(path))
                || stage.stdin.is_some() && stage.stdin == stage.stdout
            {
                return Err("stdout cannot overwrite another output or its own stdin".into());
            }
        }
    }
    if matrix
        .comparisons
        .iter()
        .any(|pair| !safe_path(&pair.left) || !safe_path(&pair.right))
    {
        return Err("comparison paths must be relative artifact paths".into());
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
}

fn append(log: &mut File, value: &impl Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *log, value).map_err(|error| error.to_string())?;
    writeln!(log)
        .and_then(|()| log.flush())
        .map_err(|error| error.to_string())
}

fn fingerprint(path: &Path) -> Result<(u64, String), String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hash = blake3::Hasher::new();
    hash.update_reader(&mut file)
        .map_err(|error| error.to_string())?;
    Ok((hash.count(), hash.finalize().to_hex().to_string()))
}

fn artifact_file(root: &Path, path: &Path) -> Result<File, String> {
    let path = root.join(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    File::create_new(path).map_err(|error| error.to_string())
}

fn expand(arg: &str, binary: &str, run_dir: &str) -> String {
    arg.split_inclusive('}')
        .fold(String::new(), |mut rendered, segment| {
            for (key, value) in [("{pyroclast}", binary), ("{run_dir}", run_dir)] {
                if let Some(prefix) = segment.strip_suffix(key) {
                    rendered.push_str(prefix);
                    rendered.push_str(value);
                    return rendered;
                }
            }
            rendered.push_str(segment);
            rendered
        })
}

fn execute(
    stage: &Stage,
    row: &Row,
    binary: &Path,
    run_dir: &Path,
    time: &Path,
) -> StageObservation {
    let argv: Vec<_> = stage
        .argv
        .iter()
        .map(|arg| expand(arg, &binary.to_string_lossy(), &run_dir.to_string_lossy()))
        .collect();
    let prefix = PathBuf::from(".measurement")
        .join(&row.name)
        .join(&stage.name);
    let resources_path = prefix.with_extension("resources.json");
    let mut report = StageObservation {
        name: stage.name.clone(),
        argv,
        wall_seconds: 0.0,
        wrapper_exit_code: None,
        wrapper_signal: None,
        error: None,
        resources: None,
    };
    let prepared = (|| -> Result<Command, String> {
        let stdout = stage
            .stdout
            .clone()
            .unwrap_or_else(|| prefix.with_extension("stdout"));
        artifact_file(run_dir, &resources_path)?;
        let mut command = Command::new(time);
        command.env("LC_ALL", "C");
        command
            .args([
                "--quiet",
                "--format",
                "{\"user_seconds\":%U,\"system_seconds\":%S,\"max_rss_kib\":%M,\"termination\":\"%Tt\",\"target_exit_code\":\"%Tx\",\"target_signal\":\"%Tn\"}",
                "--output",
            ])
            .arg(run_dir.join(&resources_path))
            .arg("--")
            .args(&report.argv)
            .stdin(match &stage.stdin {
                Some(path) => {
                    Stdio::from(File::open(run_dir.join(path)).map_err(|error| error.to_string())?)
                }
                None => Stdio::null(),
            })
            .stdout(artifact_file(run_dir, &stdout).map(Stdio::from)?)
            .stderr(
                artifact_file(run_dir, &prefix.with_extension("stderr")).map(Stdio::from)?,
            );
        Ok(command)
    })();
    match prepared {
        Ok(mut command) => {
            let started = Instant::now();
            let status = command.status();
            report.wall_seconds = started.elapsed().as_secs_f64();
            match status {
                Ok(status) => {
                    report.wrapper_exit_code = status.code();
                    #[cfg(unix)]
                    {
                        report.wrapper_signal = status.signal();
                    }
                }
                Err(error) => report.error = Some(error.to_string()),
            }
            let resources = std::fs::read(run_dir.join(&resources_path))
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
                });
            match resources {
                Ok(resources) => report.resources = Some(resources),
                Err(error) => {
                    report.error = Some(format!(
                        "resource report unavailable: {error}; launch: {:?}",
                        report.error
                    ));
                }
            }
        }
        Err(error) => report.error = Some(error),
    }
    report
}

fn compare(pair: &Comparison, run_dir: &Path) -> ComparisonObservation {
    let result = (|| -> Result<bool, String> {
        let left_path = run_dir.join(&pair.left);
        let right_path = run_dir.join(&pair.right);
        if left_path
            .canonicalize()
            .map_err(|error| error.to_string())?
            == right_path
                .canonicalize()
                .map_err(|error| error.to_string())?
        {
            return Err("comparison endpoints must be independent files".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let left = left_path.metadata().map_err(|error| error.to_string())?;
            let right = right_path.metadata().map_err(|error| error.to_string())?;
            if (left.dev(), left.ino()) == (right.dev(), right.ino()) {
                return Err("comparison endpoints must not be hardlinks".into());
            }
        }
        let left = fingerprint(&run_dir.join(&pair.left))?;
        let right = fingerprint(&run_dir.join(&pair.right))?;
        if left.0 == 0 || right.0 == 0 {
            return Err("empty artifacts cannot prove parity".into());
        }
        Ok(left == right)
    })();
    ComparisonObservation {
        left: pair.left.clone(),
        right: pair.right.clone(),
        matches: result.as_ref().is_ok_and(|matches| *matches),
        error: result.err(),
    }
}

fn prepare(matrix: &Matrix, binary: &Path, out: &Path, time: &Path) -> Result<File, String> {
    let identity = fingerprint(binary)?;
    let inputs: Vec<_> = matrix.inputs.iter().map(|path| {
        fingerprint(path).map(|identity| serde_json::json!({"path": path, "bytes": identity.0, "blake3": identity.1}))
    }).collect::<Result<_, _>>()?;
    let version = Command::new(time)
        .arg("--version")
        .output()
        .map_err(|error| error.to_string())?;
    let version = String::from_utf8_lossy(&version.stdout);
    if !version.contains("GNU Time") {
        return Err("--time must be GNU time".into());
    }
    let capability = Command::new(time)
        .args([
            "--quiet",
            "--format",
            "%Tt|%Tx|%Tn",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !capability.status.success() || capability.stderr != b"normal|0|\n" {
        return Err("GNU time with target termination formats (%Tt/%Tx/%Tn) is required".into());
    }
    std::fs::create_dir(out).map_err(|error| error.to_string())?;
    std::fs::write(
        out.join("identity.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "pyroclast": binary, "bytes": identity.0, "blake3": identity.1,
            "inputs": inputs, "time_version": version
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let mut log =
        File::create(out.join("observations.jsonl")).map_err(|error| error.to_string())?;
    append(
        &mut log,
        &serde_json::json!({"event": "metadata", "matrix": matrix,
            "os": std::env::consts::OS, "architecture": std::env::consts::ARCH,
            "cwd": std::env::current_dir().map_err(|error| error.to_string())?,
            "command_locale": "C",
            "memory_scope": "GNU time maximum RSS of a command and waited-for children; not simultaneous process-tree RSS or owned heap",
            "timing_scope": "monotonic command wall time including GNU time launch; row includes stage orchestration; artifact comparison excluded"
        }),
    )?;
    Ok(log)
}

fn measure_row(
    row: &Row,
    repetition: usize,
    binary: &Path,
    run_dir: &Path,
    time: &Path,
    log: &mut File,
) -> Result<Observation, String> {
    append(
        log,
        &serde_json::json!({"event": "row_started", "repetition": repetition, "row": row.name}),
    )?;
    let started = Instant::now();
    let mut complete = true;
    let mut stages = Vec::new();
    for stage in &row.stages {
        append(
            log,
            &serde_json::json!({"event": "stage_started", "repetition": repetition, "row": row.name, "stage": stage.name}),
        )?;
        let observation = execute(stage, row, binary, run_dir, time);
        complete = observation.wrapper_exit_code == Some(0) && observation.error.is_none();
        append(
            log,
            &serde_json::json!({"event": "stage_finished", "repetition": repetition, "row": row.name, "observation": observation}),
        )?;
        stages.push(observation);
        if !complete {
            break;
        }
    }
    let wall_seconds = started.elapsed().as_secs_f64();
    let artifact_errors: Vec<_> = row
        .required_artifacts
        .iter()
        .filter_map(|path| match run_dir.join(path).metadata() {
            Ok(metadata) if metadata.is_file() && metadata.len() > 0 => None,
            _ => Some(format!(
                "required artifact missing, empty or not a file: {}",
                path.display()
            )),
        })
        .collect();
    complete &= artifact_errors.is_empty();
    let observation = Observation {
        repetition,
        row: row.name.clone(),
        wall_seconds,
        complete,
        stages,
        comparisons: Vec::new(),
        artifact_errors,
    };
    append(
        log,
        &serde_json::json!({"event": "row_finished", "observation": observation}),
    )?;
    Ok(observation)
}

fn accepted(observations: &[Observation]) -> bool {
    observations
        .iter()
        .all(|row| row.complete && row.comparisons.iter().all(|pair| pair.matches))
}

fn canonical_output(
    out: &Path,
    canonicalize: impl FnOnce(&Path) -> std::io::Result<PathBuf>,
) -> Result<PathBuf, String> {
    let out = canonicalize(out).map_err(|error| error.to_string())?;
    if out.to_str().is_none() {
        return Err("canonical JSON measurement output must be UTF-8".into());
    }
    Ok(out)
}

fn measure_with_time(
    matrix: &Matrix,
    binary: &Path,
    out: &Path,
    time: &Path,
) -> Result<Vec<Observation>, String> {
    validate(matrix)?;
    let binary = binary.canonicalize().map_err(|error| error.to_string())?;
    if binary.to_str().is_none() || out.to_str().is_none() {
        return Err("JSON measurement paths must be UTF-8".into());
    }
    let mut log = prepare(matrix, &binary, out, time)?;
    let out = canonical_output(out, Path::canonicalize)?;
    let mut observations = Vec::new();
    for repetition in 0..matrix.repetitions {
        let run_dir = out.join(repetition.to_string());
        std::fs::create_dir(&run_dir).map_err(|error| error.to_string())?;
        let mut order: Vec<_> = matrix.rows.iter().collect();
        if repetition % 2 == 1 {
            order.reverse();
        }
        let first = observations.len();
        for row in order {
            observations.push(measure_row(
                row, repetition, &binary, &run_dir, time, &mut log,
            )?);
        }
        let all_complete = observations[first..].iter().all(|row| row.complete);
        let comparisons: Vec<_> = matrix
            .comparisons
            .iter()
            .map(|pair| {
                if all_complete {
                    compare(pair, &run_dir)
                } else {
                    ComparisonObservation {
                        left: pair.left.clone(),
                        right: pair.right.clone(),
                        matches: false,
                        error: Some("incomplete workflow; parity not evaluated".into()),
                    }
                }
            })
            .collect();
        append(
            &mut log,
            &serde_json::json!({"event": "comparisons", "repetition": repetition, "observations": comparisons}),
        )?;
        observations[first].comparisons = comparisons;
    }
    let mut summary = File::create(out.join("summary.json")).map_err(|error| error.to_string())?;
    append(&mut summary, &observations)?;
    Ok(observations)
}

fn run(args: &Args) -> Result<bool, String> {
    let matrix: Matrix =
        serde_json::from_slice(&std::fs::read(&args.matrix).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let observations = measure_with_time(&matrix, &args.pyroclast, &args.out, &args.time)?;
    println!(
        "{}",
        serde_json::to_string(&observations).map_err(|error| error.to_string())?
    );
    Ok(accepted(&observations))
}

fn main() -> ExitCode {
    match run(&Args::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrix(value: serde_json::Value) -> Matrix {
        serde_json::from_value(value).unwrap()
    }

    fn measure(matrix: &Matrix, out: &Path) -> Result<Vec<Observation>, String> {
        measure_with_time(
            matrix,
            &std::env::current_exe().unwrap(),
            out,
            Path::new("time"),
        )
    }

    #[test]
    fn alternates_row_order_and_preserves_argument_boundaries() {
        let root = tempfile::tempdir().unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 2,
            "rows": [
                {"name": "pyro", "stages": [{"name": "capture", "argv": [
                    "sh", "-c", "printf '%s\\n' \"$1\" >> \"$2\"", "sh",
                    "pyro value; not a shell command", "{run_dir}/order"
                ]}]},
                {"name": "native", "stages": [{"name": "capture", "argv": [
                    "sh", "-c", "printf '%s\\n' native >> \"$1\"", "sh", "{run_dir}/order"
                ]}]}
            ], "comparisons": []
        }));
        let out = root.path().join("measurements");
        let observations = measure(&spec, &out).unwrap();
        assert!(observations.iter().all(|row| row.complete));
        assert_eq!(
            std::fs::read_to_string(out.join("0/order")).unwrap(),
            "pyro value; not a shell command\nnative\n"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("1/order")).unwrap(),
            "native\npyro value; not a shell command\n"
        );
    }

    #[test]
    fn comparison_mismatch_prevents_acceptance_despite_successful_commands() {
        let root = tempfile::tempdir().unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 1,
            "rows": [{"name": "shared-recording", "stages": [{"name": "outputs", "argv": [
                "sh", "-c", "printf 'a 1\\n' > \"$1/left\"; printf 'a 2\\n' > \"$1/right\"",
                "sh", "{run_dir}"
            ]}]}],
            "comparisons": [{"left": "left", "right": "right"}]
        }));
        let observations = measure(&spec, &root.path().join("out")).unwrap();
        assert!(!accepted(&observations), "mismatched outputs accepted");
    }

    #[test]
    fn launch_failure_is_retained_and_does_not_erase_later_rows() {
        let root = tempfile::tempdir().unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 1,
            "rows": [
                {"name": "missing", "stages": [{"name": "capture", "argv": ["/no/such/executable"]}]},
                {"name": "baseline", "stages": [{"name": "workload", "argv": ["sh", "-c", "exit 0"]}]}
            ], "comparisons": []
        }));
        let observations = measure(&spec, &root.path().join("out"))
            .expect("launch failures must be observations, not discard the run");
        assert_eq!(observations.len(), 2);
        assert!(!observations[0].complete);
        assert!(observations[1].complete);
    }

    #[test]
    fn substituted_paths_are_not_interpreted_as_new_placeholders() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("binary {run_dir}");
        std::fs::write(&binary, "binary identity").unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 1,
            "rows": [{"name": "arguments", "stages": [{"name": "print", "argv": [
                "sh", "-c", "printf '%s' \"$1\"", "sh", "{pyroclast}"
            ], "stdout": "argument"}]}], "comparisons": []
        }));
        let out = root.path().join("out");
        measure_with_time(&spec, &binary, &out, Path::new("time")).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("0/argument")).unwrap(),
            binary.canonicalize().unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn failed_stage_keeps_exit_and_logs_and_never_runs_downstream_stages() {
        let root = tempfile::tempdir().unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 1,
            "rows": [{"name": "native", "stages": [
                {"name": "capture", "argv": ["sh", "-c", "printf partial; printf diagnostic >&2; exit 42"]},
                {"name": "render", "argv": ["sh", "-c", "touch \"$1/should-not-run\"", "sh", "{run_dir}"]}
            ]}], "comparisons": []
        }));
        let out = root.path().join("out");
        let observations = measure(&spec, &out).unwrap();
        assert!(!accepted(&observations));
        assert_eq!(observations[0].stages.len(), 1);
        assert_eq!(observations[0].stages[0].wrapper_exit_code, Some(42));
        assert_eq!(
            std::fs::read_to_string(out.join("0/.measurement/native/capture.stdout")).unwrap(),
            "partial"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("0/.measurement/native/capture.stderr")).unwrap(),
            "diagnostic"
        );
        assert!(!out.join("0/should-not-run").exists());
        let events: Vec<serde_json::Value> =
            std::fs::read_to_string(out.join("observations.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
        assert_eq!(events[1]["event"], "row_started");
        assert_eq!(events[2]["event"], "stage_started");
        assert_eq!(events[3]["observation"]["wrapper_exit_code"], 42);
        assert!(observations[0].stages[0].resources.is_some());
    }

    #[test]
    fn rejects_empty_or_missing_parity_artifacts_and_keeps_successful_timing() {
        for command in [
            "touch \"$1/left\" \"$1/right\"",
            "printf 'a 1\\n' > \"$1/left\"",
        ] {
            let root = tempfile::tempdir().unwrap();
            let spec = matrix(serde_json::json!({
                "repetitions": 1,
                "rows": [{"name": "outputs", "stages": [{"name": "create", "argv": ["sh", "-c", command, "sh", "{run_dir}"]}]}],
                "comparisons": [{"left": "left", "right": "right"}]
            }));
            let observations = measure(&spec, &root.path().join("out")).unwrap();
            assert!(observations[0].complete);
            assert!(observations[0].stages[0].wall_seconds > 0.0);
            assert!(!accepted(&observations));
            assert!(observations[0].comparisons[0].error.is_some());
        }
    }

    #[test]
    fn required_artifact_must_be_a_nonempty_file() {
        for command in ["true", "touch \"$1/profile\"", "mkdir \"$1/profile\""] {
            let root = tempfile::tempdir().unwrap();
            let spec = matrix(serde_json::json!({
                "repetitions": 1,
                "rows": [{"name": "capture", "required_artifacts": ["profile"],
                    "stages": [{"name": "profile", "argv": ["sh", "-c", command, "sh", "{run_dir}"]}]}],
                "comparisons": []
            }));
            let observations = measure(&spec, &root.path().join("out")).unwrap();
            assert!(!accepted(&observations));
            assert_eq!(observations[0].stages[0].wrapper_exit_code, Some(0));
            assert_eq!(observations[0].artifact_errors.len(), 1);
        }
    }

    #[test]
    fn successful_stages_support_stdin_and_record_comparisons_outside_timing() {
        let root = tempfile::tempdir().unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 1,
            "rows": [{"name": "pipeline", "required_artifacts": ["nested/right"], "stages": [
                {"name": "export", "argv": ["sh", "-c", "printf 'frame 1\\n'"], "stdout": "left"},
                {"name": "fold", "argv": ["cat"], "stdin": "left", "stdout": "nested/right"}
            ]}], "comparisons": [{"left": "left", "right": "nested/right"}]
        }));
        let observations = measure(&spec, &root.path().join("out")).unwrap();
        assert!(accepted(&observations));
        assert_eq!(observations[0].stages.len(), 2);
        assert!(observations[0].comparisons[0].matches);
        assert!(
            observations[0].wall_seconds
                >= observations[0]
                    .stages
                    .iter()
                    .map(|stage| stage.wall_seconds)
                    .sum()
        );
    }

    #[test]
    fn existing_output_and_invalid_matrix_are_rejected_without_workload_launch() {
        let root = tempfile::tempdir().unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 1, "rows": [{"name": "baseline", "stages": [{"name": "workload", "argv": ["true"]}]}], "comparisons": []
        }));
        assert!(measure(&spec, root.path()).is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        for invalid in [
            serde_json::json!({"repetitions": 0, "rows": [], "comparisons": []}),
            serde_json::json!({"repetitions": 1, "rows": [{"name": "../escape", "stages": []}], "comparisons": []}),
            serde_json::json!({"repetitions": 1, "rows": [{"name": "empty", "stages": [{"name": "stage", "argv": []}]}], "comparisons": []}),
            serde_json::json!({"repetitions": 1, "rows": [{"name": "escape", "stages": [{"name": "stage", "argv": ["true"], "stdout": "../escape"}]}], "comparisons": []}),
        ] {
            assert!(measure(&matrix(invalid), &root.path().join("out")).is_err());
            assert!(!root.path().join("out").exists());
        }
    }

    #[test]
    fn row_and_stage_names_cannot_collide_in_runner_logs() {
        let root = tempfile::tempdir().unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 1, "rows": [
                {"name": "a-b", "stages": [{"name": "c", "argv": ["sh", "-c", "printf first"]}]},
                {"name": "a", "stages": [{"name": "b-c", "argv": ["sh", "-c", "printf second"]}]}
            ], "comparisons": []
        }));
        let out = root.path().join("out");
        let observations = measure(&spec, &out).unwrap();
        assert!(accepted(&observations));
        // Independent command output must survive subsequent rows.
        let logs = out.join("0");
        assert_eq!(
            std::fs::read_to_string(logs.join(".measurement/a-b/c.stdout")).unwrap(),
            "first"
        );
        assert_eq!(
            std::fs::read_to_string(logs.join(".measurement/a/b-c.stdout")).unwrap(),
            "second"
        );
    }

    #[test]
    fn identical_or_aliased_outputs_do_not_prove_independent_parity() {
        for right in ["left", "alias"] {
            let root = tempfile::tempdir().unwrap();
            let spec = matrix(serde_json::json!({
                "repetitions": 1, "rows": [{"name": "outputs", "stages": [{"name": "create", "argv": [
                    "sh", "-c", "printf 'frame 1\\n' > \"$1/left\"; ln \"$1/left\" \"$1/alias\"", "sh", "{run_dir}"
                ]}]}], "comparisons": [{"left": "left", "right": right}]
            }));
            let observations = measure(&spec, &root.path().join("out")).unwrap();
            assert!(
                !accepted(&observations),
                "self-comparison accepted as parity"
            );
        }
    }

    #[test]
    fn configured_outputs_cannot_alias_inputs_or_runner_owned_evidence() {
        for stage in [
            serde_json::json!({"name": "capture", "argv": ["cat"], "stdin": "input", "stdout": "input"}),
            serde_json::json!({"name": "capture", "argv": ["true"], "stdout": ".measurement/native/capture.resources.json"}),
        ] {
            let spec = matrix(serde_json::json!({"repetitions": 1,
                "rows": [{"name": "native", "stages": [stage]}], "comparisons": []
            }));
            assert!(
                validate(&spec).is_err(),
                "unsafe evidence path was accepted"
            );
        }
    }

    #[test]
    fn target_signal_is_distinct_from_normal_exit_with_same_wrapper_status() {
        let root = tempfile::tempdir().unwrap();
        let spec = matrix(serde_json::json!({
            "repetitions": 1, "rows": [
                {"name": "signaled", "stages": [{"name": "target", "argv": ["sh", "-c", "kill -TERM $$"]}]},
                {"name": "exited", "stages": [{"name": "target", "argv": ["sh", "-c", "exit 143"]}]}
            ], "comparisons": []
        }));
        let observations = measure(&spec, &root.path().join("out")).unwrap();
        assert!(!accepted(&observations));
        let signaled = serde_json::to_value(&observations[0].stages[0]).unwrap();
        let exited = serde_json::to_value(&observations[1].stages[0]).unwrap();
        assert_eq!(signaled["resources"]["termination"], "signalled");
        assert_eq!(signaled["resources"]["target_signal"], "15");
        assert_eq!(exited["resources"]["termination"], "normal");
        assert_eq!(exited["resources"]["target_exit_code"], "143");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_canonical_output_is_rejected_before_launch() {
        use std::os::unix::ffi::OsStringExt;
        let resolved = PathBuf::from(std::ffi::OsString::from_vec(vec![b'd', 0xff]));
        // Some native filesystems reject raw-byte names; exercise the I/O
        // boundary without requiring one to create such a directory.
        assert!(
            canonical_output(Path::new("ascii-link/out"), |_| Ok(resolved)).is_err(),
            "canonical output was accepted with lossy argv expansion"
        );
    }
}
