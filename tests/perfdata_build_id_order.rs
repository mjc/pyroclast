#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use pyroclast::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER;
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
};

fn record(kind: u32, misc: u16, mut payload: Vec<u8>) -> Vec<u8> {
    payload.resize((8 + payload.len()).next_multiple_of(8) - 8, 0);
    let mut bytes = kind.to_le_bytes().to_vec();
    bytes.extend(misc.to_le_bytes());
    bytes.extend(u16::try_from(8 + payload.len()).unwrap().to_le_bytes());
    bytes.extend(payload);
    bytes
}

fn build_id(path: &Path, misc: u16) -> Vec<u8> {
    build_id_value(path, misc, 0x22)
}

fn build_id_value(path: &Path, misc: u16, id: u8) -> Vec<u8> {
    let mut bytes = u32::MAX.to_le_bytes().to_vec();
    bytes.extend([id; 20]);
    bytes.extend([0; 4]);
    bytes.extend(path.as_os_str().as_encoded_bytes());
    bytes.push(0);
    record(67, misc, bytes)
}

fn recording(records: Vec<Vec<u8>>, ordered: bool) -> Vec<u8> {
    let mut header = vec![0; 104];
    header[..8].copy_from_slice(b"PERFILE2");
    for (offset, value) in [
        (8, 104),
        (16, 144),
        (24, 104),
        (32, 144),
        (40, 248),
        (
            48,
            u64::try_from(records.iter().map(Vec::len).sum::<usize>()).unwrap(),
        ),
    ] {
        header[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut attr = vec![0; 144];
    attr[..4].copy_from_slice(&1_u32.to_le_bytes());
    attr[4..8].copy_from_slice(&128_u32.to_le_bytes());
    attr[16..24].copy_from_slice(&1_u64.to_le_bytes());
    let flags = PERF_SAMPLE_IP
        | PERF_SAMPLE_TID
        | PERF_SAMPLE_TIME
        | PERF_SAMPLE_CALLCHAIN
        | PERF_SAMPLE_PERIOD;
    attr[24..32].copy_from_slice(&flags.to_le_bytes());
    attr[40..48].copy_from_slice(&(u64::from(ordered) << 18).to_le_bytes());
    header.extend(attr);
    header.extend(records.into_iter().flatten());
    header
}

fn compile_elf(root: &Path, name: &str, id: u8) -> PathBuf {
    let source = root.join(format!("{name}.S"));
    let binary = root.join(format!("{name}.elf"));
    std::fs::write(&source, format!(".text\n.globl {name}\n.type {name},@function\n{name}:\n.fill 32,1,0x90\nret\n.size {name},.-{name}\n.section .note.GNU-stack,\"\",@progbits\n")).unwrap();
    let output = Command::new("cc")
        .args(["-nostdlib", "-no-pie", "-Wl,-Ttext=0x401000"])
        .arg(format!("-Wl,-e,{name}"))
        .arg(format!(
            "-Wl,--build-id=0x{}",
            format!("{id:02x}").repeat(20)
        ))
        .arg(source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn assert_native_parity(data: &Path, home: &Path, expected: &[&str]) {
    let debug = home.join(".debug");
    for mode in ["--inline", "--no-inline"] {
        let native = Command::new("perf")
            .arg("--buildid-dir")
            .arg(&debug)
            .args(["script", "--force", mode, "-i"])
            .arg(data)
            .env("DEBUGINFOD_URLS", "")
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{}: {}",
            data.display(),
            String::from_utf8_lossy(&native.stderr)
        );
        let script = String::from_utf8(native.stdout).unwrap();
        for expected in expected {
            assert!(
                script.contains(expected),
                "native {} lacks {expected}: {script}",
                data.display()
            );
        }
        let script_path = data.with_extension(format!("{mode}.script"));
        std::fs::write(&script_path, &script).unwrap();
        let native_folded = Command::new("inferno-collapse-perf")
            .arg(&script_path)
            .output()
            .unwrap();
        assert!(
            native_folded.status.success(),
            "{}",
            String::from_utf8_lossy(&native_folded.stderr)
        );
        assert!(!native_folded.stdout.is_empty());
        for symbolizer in ["rust-addr2line", "addr2line"] {
            for (command, reference) in [
                ("perf-script", script.as_bytes()),
                ("fold", native_folded.stdout.as_slice()),
            ] {
                let output = Command::new(env!("CARGO_BIN_EXE_pyroclast"))
                    .args(["plumbing", command, mode, "--symbolizer", symbolizer])
                    .arg(data)
                    .env("HOME", home)
                    .env("DEBUGINFOD_URLS", "")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(
                    String::from_utf8(output.stdout).unwrap(),
                    String::from_utf8_lossy(reference),
                    "{}, {command}, {mode}, {symbolizer}",
                    data.display()
                );
            }
        }
        let options = pyroclast::perfdata::fold::FoldOptions {
            inline: mode == "--inline",
            count_periods: true,
        };
        let resolver = pyroclast::symbols::PerfSymbolResolver::from_object_resolver(
            pyroclast::symbols::RustAddr2lineResolver::new(),
        )
        .with_debug_dir(debug.clone());
        let bytes = std::fs::read(data).unwrap();
        for folded in [
            pyroclast::perfdata::fold::fold_perfdata_callchains_with_symbols(
                &bytes, options, &resolver,
            )
            .unwrap(),
            pyroclast::perfdata::fold::fold_perfdata_file_with_symbols(data, options, &resolver)
                .unwrap(),
        ] {
            assert_eq!(
                folded.as_bytes(),
                native_folded.stdout,
                "{}, {mode}, library replay",
                data.display()
            );
        }
    }
}

fn mapping(path: &Path, build_id: Option<u8>) -> Vec<u8> {
    let mut bytes = 11_u32.to_le_bytes().to_vec();
    bytes.extend(12_u32.to_le_bytes());
    for value in [0x0040_0000_u64, 0x0001_0000, 0] {
        bytes.extend(value.to_le_bytes());
    }
    if let Some(id) = build_id {
        bytes.extend([20, 0, 0, 0]);
        bytes.extend([id; 20]);
        bytes.extend(5_u32.to_le_bytes());
        bytes.extend(2_u32.to_le_bytes());
    }
    bytes.extend(path.as_os_str().as_encoded_bytes());
    bytes.push(0);
    let (kind, misc) = if build_id.is_some() {
        (
            10,
            pyroclast::perfdata::records::PERF_RECORD_MISC_MMAP_BUILD_ID,
        )
    } else {
        (1, 0)
    };
    record(kind, misc | PERF_RECORD_MISC_CPUMODE_USER, bytes)
}

fn sample(time: u64, ip: u64) -> Vec<u8> {
    let mut payload = ip.to_le_bytes().to_vec();
    payload.extend(11_u32.to_le_bytes());
    payload.extend(12_u32.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload.extend(1_u64.to_le_bytes());
    payload.extend(2_u64.to_le_bytes());
    payload.extend(0xffff_ffff_ffff_fe00_u64.to_le_bytes());
    payload.extend(ip.to_le_bytes());
    record(9, PERF_RECORD_MISC_CPUMODE_USER, payload)
}

#[test]
fn native_perf_stream_build_ids_obey_delivery_order_and_keep_loaded_symbols() {
    // perf header.c:2714 and session.c:1649 distinguish feature initialization
    // from stream events. symbol.c:1705/1866 never reloads a loaded DSO merely
    // because header.c:5232 later sets a different build ID.
    let root = tempfile::tempdir().unwrap();
    let live = compile_elf(root.path(), "live_leaf", 0x11);
    let cached = compile_elf(root.path(), "cached_leaf", 0x22);
    let home = root.path().join("home");
    let debug = home.join(".debug");
    let cache = pyroclast::symbols::perf_build_id_elf_path(&debug, &"22".repeat(20));
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::copy(cached, cache).unwrap();
    let mapping = mapping(&live, None);
    let mut queued_mapping = mapping.clone();
    queued_mapping.extend(11_u32.to_le_bytes());
    queued_mapping.extend(12_u32.to_le_bytes());
    queued_mapping.extend(0_u64.to_le_bytes());
    let queued_size = u16::try_from(queued_mapping.len()).unwrap();
    queued_mapping[6..8].copy_from_slice(&queued_size.to_le_bytes());
    let event = || build_id(&live, PERF_RECORD_MISC_CPUMODE_USER);
    for (name, expected, ordered, records) in [
        (
            "late",
            "live_leaf",
            false,
            vec![
                mapping.clone(),
                sample(1_000_000_000, 0x0040_1001),
                event(),
                sample(2_000_000_000, 0x0040_1002),
            ],
        ),
        (
            "early",
            "cached_leaf",
            false,
            vec![event(), mapping.clone(), sample(1_000_000_000, 0x0040_1001)],
        ),
        (
            "after-map",
            "cached_leaf",
            false,
            vec![mapping.clone(), event(), sample(1_000_000_000, 0x0040_1001)],
        ),
        (
            "invalid-mode",
            "live_leaf",
            false,
            vec![
                build_id(&live, 0),
                mapping.clone(),
                sample(1_000_000_000, 0x0040_1001),
            ],
        ),
        (
            "late-queued",
            "cached_leaf",
            true,
            vec![queued_mapping, sample(1_000_000_000, 0x0040_1001), event()],
        ),
    ] {
        let data = root.path().join(format!("{name}.perf.data"));
        std::fs::write(&data, recording(records, ordered)).unwrap();
        assert_native_parity(&data, &home, &[expected]);
    }
}

#[test]
fn native_perf_discovered_elf_id_distinguishes_a_later_mmap2_identity() {
    // symbol.c:dso__load fills a missing ID from the ELF before loading symbols.
    // machine.c:1728 passes a later MMAP2 ID to the DSO identity lookup, so a
    // different ID creates a different DSO rather than reloading the old one.
    let root = tempfile::tempdir().unwrap();
    let live = compile_elf(root.path(), "live_leaf", 0x11);
    let cached = compile_elf(root.path(), "cached_leaf", 0x22);
    let home = root.path().join("home");
    let cache = pyroclast::symbols::perf_build_id_elf_path(&home.join(".debug"), &"22".repeat(20));
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::copy(cached, cache).unwrap();
    let data = root.path().join("remapped.perf.data");
    std::fs::write(
        &data,
        recording(
            vec![
                mapping(&live, None),
                sample(1_000_000_000, 0x0040_1001),
                mapping(&live, Some(0x22)),
                sample(2_000_000_000, 0x0040_1002),
            ],
            false,
        ),
    )
    .unwrap();
    assert_native_parity(&data, &home, &["live_leaf+0x1", "cached_leaf+0x2"]);
}

#[test]
fn native_perf_discovered_elf_id_selects_its_build_id_cache() {
    // symbol.c:dso__load reads a missing live ELF ID before iterating the
    // DSO_BINARY_TYPE__BUILD_ID_CACHE candidates, not only after symbol lookup.
    let root = tempfile::tempdir().unwrap();
    let live = compile_elf(root.path(), "live_leaf", 0x11);
    let cached = compile_elf(root.path(), "cached_auto_leaf", 0x11);
    let home = root.path().join("home");
    let cache = pyroclast::symbols::perf_build_id_elf_path(&home.join(".debug"), &"11".repeat(20));
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::copy(cached, cache).unwrap();
    let data = root.path().join("auto-cache.perf.data");
    std::fs::write(
        &data,
        recording(
            vec![mapping(&live, None), sample(1_000_000_000, 0x0040_1001)],
            false,
        ),
    )
    .unwrap();
    assert_native_parity(&data, &home, &["cached_auto_leaf+0x1"]);
}

#[test]
fn native_perf_failed_dso_load_is_not_retried_after_a_stream_build_id() {
    // symbol.c:dso__load always sets loaded at out, including missing ELF.
    let root = tempfile::tempdir().unwrap();
    let live = root.path().join("missing.elf");
    let cached = compile_elf(root.path(), "cached_leaf", 0x22);
    let home = root.path().join("home");
    let cache = pyroclast::symbols::perf_build_id_elf_path(&home.join(".debug"), &"22".repeat(20));
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::copy(cached, cache).unwrap();
    let data = root.path().join("missing.perf.data");
    std::fs::write(
        &data,
        recording(
            vec![
                mapping(&live, None),
                sample(1_000_000_000, 0x0040_1001),
                build_id(&live, PERF_RECORD_MISC_CPUMODE_USER),
                sample(2_000_000_000, 0x0040_1002),
            ],
            false,
        ),
    )
    .unwrap();
    assert_native_parity(&data, &home, &["401001 [unknown]", "401002 [unknown]"]);
}

#[test]
fn native_perf_cleared_build_id_retains_loaded_symbols_when_mmap2_enriches_it() {
    // header.c:__event_process_build_id sets even zero IDs. dso.c:
    // __dso__improve_id can enrich that undefined ID without reloading symbols.
    let root = tempfile::tempdir().unwrap();
    let live = compile_elf(root.path(), "live_leaf", 0x11);
    let cached = compile_elf(root.path(), "cached_leaf", 0x22);
    let home = root.path().join("home");
    let cache = pyroclast::symbols::perf_build_id_elf_path(&home.join(".debug"), &"22".repeat(20));
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::copy(cached, cache).unwrap();
    let mut clear = build_id(&live, PERF_RECORD_MISC_CPUMODE_USER);
    clear[12..32].fill(0);
    let data = root.path().join("cleared.perf.data");
    std::fs::write(
        &data,
        recording(
            vec![
                mapping(&live, None),
                sample(1_000_000_000, 0x0040_1001),
                clear,
                mapping(&live, Some(0x22)),
                sample(2_000_000_000, 0x0040_1002),
            ],
            false,
        ),
    )
    .unwrap();
    assert_native_parity(&data, &home, &["live_leaf+0x1", "live_leaf+0x2"]);
}

#[test]
fn native_perf_stream_build_id_preserves_lookup_order_of_loaded_dsos() {
    // dso.c:dso__set_build_id writes the ID without invalidating dsos->sorted.
    // Unlike __dso__improve_id, it must not reorder same-path DSO identities.
    // dsos.c:__dsos__find_by_longname_id selects the existing middle entry for
    // a later wildcard mapping, even after its ID becomes smaller than its peer.
    let root = tempfile::tempdir().unwrap();
    let live = compile_elf(root.path(), "live_leaf", 0x11);
    let home = root.path().join("home");
    for (name, id) in [("cached_first", 0x11), ("cached_second", 0x22)] {
        let cached = compile_elf(root.path(), name, id);
        let cache = pyroclast::symbols::perf_build_id_elf_path(
            &home.join(".debug"),
            &format!("{id:02x}").repeat(20),
        );
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::copy(cached, cache).unwrap();
    }
    let data = root.path().join("lookup-order.perf.data");
    std::fs::write(
        &data,
        recording(
            vec![
                mapping(&live, Some(0x11)),
                sample(1_000_000_000, 0x0040_1001),
                mapping(&live, Some(0x22)),
                sample(2_000_000_000, 0x0040_1002),
                build_id_value(&live, PERF_RECORD_MISC_CPUMODE_USER, 0x05),
                mapping(&live, None),
                sample(3_000_000_000, 0x0040_1003),
            ],
            false,
        ),
    )
    .unwrap();
    assert_native_parity(
        &data,
        &home,
        &["cached_first+0x1", "cached_second+0x2", "cached_second+0x3"],
    );
}
