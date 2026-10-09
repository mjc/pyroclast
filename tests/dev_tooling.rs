#[test]
fn devenv_and_precommit_use_nextest() {
    let devenv = std::fs::read_to_string("devenv.nix").expect("devenv");
    let hook = std::fs::read_to_string(".githooks/pre-commit").expect("pre-commit hook");
    let bench_script = std::fs::read_to_string("scripts/pyroclast-bench").expect("bench script");
    let bench_example =
        std::fs::read_to_string("examples/pyroclast-bench.rs").expect("bench example");

    assert!(devenv.contains("languages.rust"));
    assert!(devenv.contains("cargo-nextest"));
    assert!(!devenv.contains("rust-src"));
    assert!(!devenv.contains("/home/"));
    assert!(hook.contains("devenv shell"));
    assert!(hook.contains("cargo fmt --check"));
    assert!(hook.contains("cargo nextest run"));
    assert!(hook.contains("cargo clippy --all-targets -- -D warnings -W clippy::pedantic"));
    assert!(hook.contains("nix flake check --no-build"));
    assert!(!hook.contains("plumbing precommit"));
    assert!(bench_script.contains("cargo run --quiet --example pyroclast-bench -- \"$@\""));
    assert!(bench_example.contains("run_bench_command"));
}

#[test]
fn flake_uses_the_reusable_crane_package() {
    let flake = std::fs::read_to_string("flake.nix").expect("flake");
    let package = std::fs::read_to_string("nix/pyroclast.nix").expect("package derivation");

    assert!(flake.contains("packages = forAllSystems"));
    assert!(flake.contains("apps = forAllSystems"));
    assert!(flake.contains("import ./nix/pyroclast.nix"));
    assert!(!flake.contains("devShells ="));
    assert!(package.contains("crane.mkLib"));
    assert!(package.contains("buildDepsOnly"));
    assert!(package.contains("buildPackage"));
}

#[test]
fn readme_documents_nextest_for_local_tests() {
    let readme = std::fs::read_to_string("README.md").expect("readme");

    assert!(readme.contains("cargo nextest run"));
}

#[test]
fn agents_documents_nextest_for_local_tests() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("agents");

    assert!(agents.contains("devenv shell"));
    assert!(agents.contains("cargo nextest run"));
}

#[cfg(unix)]
#[test]
fn precommit_uses_current_project_environment_and_preserves_required_gates() {
    let output = std::process::Command::new("bash")
        .arg("scripts/tests/hook-environment.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(unix)]
#[test]
fn native_parity_generates_fresh_portable_inputs_and_preserves_explicit_failures() {
    let output = std::process::Command::new("bash")
        .arg("scripts/tests/native-parity-inputs.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(unix)]
#[test]
fn native_parity_dispatches_platform_and_requires_darwin_record_export_comparison() {
    let output = std::process::Command::new("bash")
        .arg("scripts/tests/native-platform-parity.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(unix)]
#[test]
fn independent_xctrace_oracle_resolves_native_cells_and_rejects_invalid_exports() {
    let output = std::process::Command::new("bash")
        .arg("scripts/tests/xctrace-oracle.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
