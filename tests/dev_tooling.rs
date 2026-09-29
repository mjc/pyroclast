#[test]
fn devenv_and_precommit_use_nextest() {
    let flake = std::fs::read_to_string("flake.nix").expect("flake");
    let devenv = std::fs::read_to_string("devenv.nix").expect("devenv");
    let hook = std::fs::read_to_string(".githooks/pre-commit").expect("pre-commit hook");
    let bench_script = std::fs::read_to_string("scripts/pyroclast-bench").expect("bench script");
    let bench_example =
        std::fs::read_to_string("examples/pyroclast-bench.rs").expect("bench example");

    assert!(flake.contains("packages = forAllSystems"));
    assert!(flake.contains("apps = forAllSystems"));
    assert!(flake.contains("crane.mkLib"));
    assert!(flake.contains("buildPackage"));
    assert!(!flake.contains("devShells ="));
    assert!(devenv.contains("languages.rust"));
    assert!(devenv.contains("cargo-nextest"));
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
