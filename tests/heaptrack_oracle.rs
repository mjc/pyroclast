#[cfg(unix)]
#[test]
fn native_heap_summary_parity_checks_footer_and_preserves_raw_input() {
    let output = std::process::Command::new("bash")
        .arg("scripts/tests/heaptrack-parity.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
