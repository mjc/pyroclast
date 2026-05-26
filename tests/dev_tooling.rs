#[test]
fn flake_and_precommit_use_nextest() {
    let flake = std::fs::read_to_string("flake.nix").expect("flake");
    let precommit =
        std::fs::read_to_string("src/bin/pyroclast-precommit.rs").expect("precommit source");

    assert!(flake.contains("cargo-nextest"));
    assert!(precommit.contains("\"nextest\""));
    assert!(precommit.contains("\"run\""));
    assert!(!precommit.contains("args: &[\"test\"]"));
}

#[test]
fn readme_documents_nextest_for_local_tests() {
    let readme = std::fs::read_to_string("README.md").expect("readme");

    assert!(readme.contains("cargo nextest run"));
}

#[test]
fn agents_documents_nextest_for_local_tests() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("agents");

    assert!(agents.contains("nix develop"));
    assert!(agents.contains("cargo nextest run"));
}
