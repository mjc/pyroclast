use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::backends::heaptrack::build_heaptrack_command;
use pyroclast::backends::linux_perf::{PerfRecordTarget, build_perf_record_command};
use pyroclast::backends::macos_xctrace::{
    build_xctrace_export_cpu_command, build_xctrace_record_command,
};
use pyroclast::backends::offcpu::{
    build_bpftrace_offcpu_command, build_perf_cpu_clock_command, build_perf_sched_record_command,
    build_perf_sched_timehist_command,
};
use pyroclast::backends::strace::build_strace_command;
use pyroclast::cli::PerfEvent;
use pyroclast::flamegraph::build_inferno_flamegraph_command;
use pyroclast::symbols::{SymbolRequest, build_addr2line_command};
use std::fmt::Write;
use std::path::PathBuf;

#[test]
fn builds_linux_perf_record_command() {
    let command = build_perf_record_command(
        PerfEvent::Default,
        997,
        "fp",
        &PathBuf::from("run/profile.raw.perf.data"),
        PerfRecordTarget::Command(vec!["cargo".to_string(), "check".to_string()]),
        3600,
    );

    assert_eq!(command.program, "perf");
    assert_eq!(
        command.args,
        vec![
            "record",
            "-F",
            "997",
            "-g",
            "--call-graph",
            "fp",
            "-o",
            "run/profile.raw.perf.data",
            "--",
            "cargo",
            "check",
        ]
    );
    assert!(command.interactive);
}

#[test]
fn builds_linux_perf_thread_record_command() {
    let command = build_perf_record_command(
        PerfEvent::TaskClock,
        199,
        "dwarf",
        &PathBuf::from("run/profile.raw.perf.data"),
        PerfRecordTarget::Threads(vec![101, 102, 103]),
        15,
    );

    assert_eq!(command.program, "perf");
    assert_eq!(
        command.args,
        vec![
            "record",
            "-e",
            "task-clock",
            "-F",
            "199",
            "-g",
            "--call-graph",
            "dwarf",
            "-t",
            "101,102,103",
            "-o",
            "run/profile.raw.perf.data",
            "--",
            "sleep",
            "15",
        ]
    );
    assert!(!command.interactive);
}

#[test]
fn builds_linux_perf_process_record_command() {
    let command = build_perf_record_command(
        PerfEvent::Cycles,
        997,
        "fp",
        &PathBuf::from("run/profile.raw.perf.data"),
        PerfRecordTarget::Process(99),
        30,
    );

    assert_eq!(command.program, "perf");
    assert_eq!(
        command.args,
        vec![
            "record",
            "-e",
            "cycles",
            "-F",
            "997",
            "-g",
            "--call-graph",
            "fp",
            "-p",
            "99",
            "-o",
            "run/profile.raw.perf.data",
            "--",
            "sleep",
            "30",
        ]
    );
    assert!(!command.interactive);
}

#[test]
fn builds_heaptrack_command() {
    let command = build_heaptrack_command(
        &PathBuf::from("run/profile.raw.heaptrack"),
        ["target/release/app".to_string(), "--serve".to_string()],
    );

    assert_eq!(command.program, "heaptrack");
    assert_eq!(
        command.args,
        vec![
            "--record-only",
            "-o",
            "run/profile.raw.heaptrack",
            "target/release/app",
            "--serve"
        ]
    );
    assert!(command.interactive);
}

#[test]
fn builds_strace_command() {
    let command = build_strace_command(
        &PathBuf::from("run/profile.raw.strace"),
        ["target/release/app".to_string(), "--serve".to_string()],
    );

    assert_eq!(command.program, "strace");
    assert_eq!(
        command.args,
        vec![
            "-f",
            "-ttt",
            "-T",
            "-o",
            "run/profile.raw.strace",
            "--",
            "target/release/app",
            "--serve",
        ]
    );
    assert!(command.interactive);
}

#[test]
fn builds_bpftrace_offcpu_command() {
    let command = build_bpftrace_offcpu_command("target/release/app --serve".to_string(), 30);

    assert_eq!(command.program, "bpftrace");
    assert_eq!(command.args[0], "-e");
    assert!(command.args[1].contains("sched:sched_switch"));
    assert_eq!(
        &command.args[2..],
        ["-c", "target/release/app --serve", "--unsafe"]
    );
    assert!(command.interactive);
}

#[test]
fn builds_perf_sched_offcpu_commands() {
    let record = build_perf_sched_record_command(
        &PathBuf::from("run/profile.raw.perf.data"),
        vec!["target/release/app".to_string(), "--serve".to_string()],
    );
    let timehist = build_perf_sched_timehist_command(&PathBuf::from("run/profile.raw.perf.data"));

    assert_eq!(record.program, "perf");
    assert_eq!(
        record.args,
        vec![
            "sched",
            "record",
            "-o",
            "run/profile.raw.perf.data",
            "--",
            "target/release/app",
            "--serve",
        ]
    );
    assert!(record.interactive);
    assert_eq!(timehist.program, "perf");
    assert_eq!(
        timehist.args,
        vec!["sched", "timehist", "-i", "run/profile.raw.perf.data"]
    );
    assert!(!timehist.interactive);
}

#[test]
fn builds_perf_cpu_clock_offcpu_command() {
    let command = build_perf_cpu_clock_command(
        997,
        "fp",
        &PathBuf::from("run/profile.raw.perf.data"),
        vec!["target/release/app".to_string(), "--serve".to_string()],
    );

    assert_eq!(command.program, "perf");
    assert_eq!(
        command.args,
        vec![
            "record",
            "-e",
            "cpu-clock",
            "-F",
            "997",
            "-g",
            "--call-graph",
            "fp",
            "-o",
            "run/profile.raw.perf.data",
            "--",
            "target/release/app",
            "--serve",
        ]
    );
    assert!(command.interactive);
}

#[test]
fn builds_inferno_flamegraph_command() {
    let command = build_inferno_flamegraph_command("CPU profile");

    assert_eq!(command.program, "inferno-flamegraph");
    assert_eq!(command.args, vec!["--title", "CPU profile", "-"]);
    assert!(!command.interactive);
}

#[test]
fn builds_macos_xctrace_record_command() {
    let command = build_xctrace_record_command(
        &PathBuf::from("run/profile.raw.xctrace.trace"),
        &PathBuf::from("run/xctrace-target.pid"),
        ["target/release/app".to_string(), "--serve".to_string()],
    );

    assert_eq!(command.program, "xctrace");
    assert_eq!(
        &command.args[..8],
        [
            "record",
            "--quiet",
            "--template",
            "CPU Profiler",
            "--output",
            "run/profile.raw.xctrace.trace",
            "--no-prompt",
            "--launch",
        ]
    );
    assert!(command.args.contains(&"/bin/sh".to_string()));
    assert!(
        command
            .args
            .iter()
            .any(|arg| arg.contains("PYROCLAST_XCTRACE_TARGET_PID"))
    );
    assert!(command.args.contains(&"target/release/app".to_string()));
    assert_eq!(
        command.env,
        vec![(
            "PYROCLAST_XCTRACE_TARGET_PID".to_string(),
            "run/xctrace-target.pid".to_string()
        )]
    );
    assert!(command.interactive);
}

#[test]
fn builds_macos_xctrace_export_command() {
    let command = build_xctrace_export_cpu_command(
        &PathBuf::from("run/profile.raw.xctrace.trace"),
        &PathBuf::from("run/profile.raw.xctrace.xml"),
    );

    assert_eq!(command.program, "xctrace");
    assert_eq!(
        command.args,
        vec![
            "export",
            "--input",
            "run/profile.raw.xctrace.trace",
            "--output",
            "run/profile.raw.xctrace.xml",
            "--xpath",
            "//table",
        ]
    );
    assert!(!command.interactive);
}

#[test]
fn builds_batched_addr2line_command() {
    let command = build_addr2line_command(
        &PathBuf::from("/bin/app"),
        &[
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
        ],
    );

    assert_eq!(command.program, "addr2line");
    assert_eq!(command.args, vec!["-f", "-C", "-e", "/bin/app"]);
    assert_eq!(command.stdin, Some(b"0x10\n0x20\n".to_vec()));
    assert!(!command.interactive);
}

fn perf_event_from_case(case: u8) -> PerfEvent {
    match case % 4 {
        0 => PerfEvent::Default,
        1 => PerfEvent::CpuClock,
        2 => PerfEvent::TaskClock,
        _ => PerfEvent::Cycles,
    }
}

proptest! {
    #[test]
    fn property_builds_linux_perf_record_command_for_generated_commands(
        event_case in any::<u8>(),
        frequency in 1_u32..20_000,
        callgraph in string_regex("[A-Za-z0-9][A-Za-z0-9,_-]{0,15}").expect("valid callgraph regex"),
        output in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid output-path regex"),
        profiled_command in prop::collection::vec(
            string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,15}").expect("valid command-arg regex"),
            1..5,
        ),
    ) {
        let event = perf_event_from_case(event_case);
        let output = PathBuf::from(output);
        let command = build_perf_record_command(
            event,
            frequency,
            &callgraph,
            &output,
            PerfRecordTarget::Command(profiled_command.clone()),
            123,
        );
        let mut expected_args = vec!["record".to_string()];
        if event != PerfEvent::Default {
            expected_args.push("-e".to_string());
            expected_args.push(event.to_string());
        }
        expected_args.extend([
            "-F".to_string(),
            frequency.to_string(),
            "-g".to_string(),
            "--call-graph".to_string(),
            callgraph.clone(),
            "-o".to_string(),
            output.display().to_string(),
            "--".to_string(),
        ]);
        expected_args.extend(profiled_command.clone());

        prop_assert_eq!(command.program, "perf");
        prop_assert_eq!(command.args, expected_args);
        prop_assert!(command.interactive);
    }

    #[test]
    fn property_builds_linux_perf_record_command_for_generated_process_attach(
        event_case in any::<u8>(),
        frequency in 1_u32..20_000,
        callgraph in string_regex("[A-Za-z0-9][A-Za-z0-9,_-]{0,15}").expect("valid process callgraph regex"),
        output in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid process output-path regex"),
        pid in 1_u32..100_000,
        duration_secs in 0_u32..10_000,
    ) {
        let event = perf_event_from_case(event_case);
        let output = PathBuf::from(output);
        let command = build_perf_record_command(
            event,
            frequency,
            &callgraph,
            &output,
            PerfRecordTarget::Process(pid),
            duration_secs,
        );
        let mut expected_args = vec!["record".to_string()];
        if event != PerfEvent::Default {
            expected_args.push("-e".to_string());
            expected_args.push(event.to_string());
        }
        expected_args.extend([
            "-F".to_string(),
            frequency.to_string(),
            "-g".to_string(),
            "--call-graph".to_string(),
            callgraph.clone(),
            "-p".to_string(),
            pid.to_string(),
            "-o".to_string(),
            output.display().to_string(),
            "--".to_string(),
            "sleep".to_string(),
            duration_secs.to_string(),
        ]);

        prop_assert_eq!(command.program, "perf");
        prop_assert_eq!(command.args, expected_args);
        prop_assert!(!command.interactive);
    }

    #[test]
    fn property_builds_linux_perf_record_command_for_generated_thread_attach(
        event_case in any::<u8>(),
        frequency in 1_u32..20_000,
        callgraph in string_regex("[A-Za-z0-9][A-Za-z0-9,_-]{0,15}").expect("valid thread callgraph regex"),
        output in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid thread output-path regex"),
        tids in prop::collection::vec(1_u32..100_000, 1..6),
        duration_secs in 0_u32..10_000,
    ) {
        let event = perf_event_from_case(event_case);
        let output = PathBuf::from(output);
        let command = build_perf_record_command(
            event,
            frequency,
            &callgraph,
            &output,
            PerfRecordTarget::Threads(tids.clone()),
            duration_secs,
        );
        let mut expected_args = vec!["record".to_string()];
        if event != PerfEvent::Default {
            expected_args.push("-e".to_string());
            expected_args.push(event.to_string());
        }
        expected_args.extend([
            "-F".to_string(),
            frequency.to_string(),
            "-g".to_string(),
            "--call-graph".to_string(),
            callgraph.clone(),
            "-t".to_string(),
            tids.iter().map(u32::to_string).collect::<Vec<_>>().join(","),
            "-o".to_string(),
            output.display().to_string(),
            "--".to_string(),
            "sleep".to_string(),
            duration_secs.to_string(),
        ]);

        prop_assert_eq!(command.program, "perf");
        prop_assert_eq!(command.args, expected_args);
        prop_assert!(!command.interactive);
    }

    #[test]
    fn property_builds_wrapper_commands_with_generated_paths_and_args(
        output in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid wrapper output-path regex"),
        raw_output in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid raw output-path regex"),
        title in string_regex("[A-Za-z0-9][A-Za-z0-9 _-]{0,23}").expect("valid flamegraph title regex"),
        profiled_command in prop::collection::vec(
            string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,15}").expect("valid wrapper command-arg regex"),
            1..5,
        ),
    ) {
        let output = PathBuf::from(output);
        let raw_output = PathBuf::from(raw_output);

        let heaptrack = build_heaptrack_command(&output, profiled_command.clone());
        prop_assert_eq!(heaptrack.program, "heaptrack");
        prop_assert_eq!(
            heaptrack.args,
            std::iter::once("--record-only".to_string())
                .chain(std::iter::once("-o".to_string()))
                .chain(std::iter::once(output.display().to_string()))
                .chain(profiled_command.clone())
                .collect::<Vec<_>>()
        );
        prop_assert!(heaptrack.interactive);

        let strace = build_strace_command(&output, profiled_command.clone());
        prop_assert_eq!(strace.program, "strace");
        prop_assert_eq!(
            strace.args,
            vec![
                "-f".to_string(),
                "-ttt".to_string(),
                "-T".to_string(),
                "-o".to_string(),
                output.display().to_string(),
                "--".to_string(),
            ]
            .into_iter()
            .chain(profiled_command.clone())
            .collect::<Vec<_>>()
        );
        prop_assert!(strace.interactive);

        let heaptrack_print = pyroclast::backends::heaptrack::build_heaptrack_print_command(&raw_output);
        prop_assert_eq!(heaptrack_print.program, "heaptrack_print");
        prop_assert_eq!(heaptrack_print.args, vec![raw_output.display().to_string()]);
        prop_assert!(!heaptrack_print.interactive);

        let inferno = build_inferno_flamegraph_command(&title);
        prop_assert_eq!(inferno.program, "inferno-flamegraph");
        prop_assert_eq!(inferno.args, vec!["--title", title.as_str(), "-"]);
        prop_assert!(!inferno.interactive);
    }

    #[test]
    fn property_builds_offcpu_and_xctrace_commands_with_generated_inputs(
        perf_output in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid perf output-path regex"),
        xctrace_trace in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid xctrace trace-path regex"),
        xctrace_pid_file in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid xctrace pid-path regex"),
        xctrace_xml in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid xctrace xml-path regex"),
        duration_secs in 0_u32..10_000,
        frequency in 1_u32..20_000,
        callgraph in string_regex("[A-Za-z0-9][A-Za-z0-9,_-]{0,15}").expect("valid offcpu callgraph regex"),
        profiled_command in prop::collection::vec(
            string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,15}").expect("valid offcpu command-arg regex"),
            1..5,
        ),
        shell_command in string_regex("[A-Za-z0-9][A-Za-z0-9 ._/-]{0,31}").expect("valid shell command regex"),
    ) {
        let perf_output = PathBuf::from(perf_output);
        let trace_path = PathBuf::from(xctrace_trace);
        let pid_file = PathBuf::from(xctrace_pid_file);
        let xml_path = PathBuf::from(xctrace_xml);

        let perf_sched_record = build_perf_sched_record_command(&perf_output, profiled_command.clone());
        prop_assert_eq!(perf_sched_record.program, "perf");
        prop_assert_eq!(
            perf_sched_record.args,
            vec![
                "sched".to_string(),
                "record".to_string(),
                "-o".to_string(),
                perf_output.display().to_string(),
                "--".to_string(),
            ]
            .into_iter()
            .chain(profiled_command.clone())
            .collect::<Vec<_>>()
        );
        prop_assert!(perf_sched_record.interactive);

        let perf_sched_timehist = build_perf_sched_timehist_command(&perf_output);
        prop_assert_eq!(perf_sched_timehist.program, "perf");
        prop_assert_eq!(
            perf_sched_timehist.args,
            vec![
                "sched".to_string(),
                "timehist".to_string(),
                "-i".to_string(),
                perf_output.display().to_string(),
            ]
        );
        prop_assert!(!perf_sched_timehist.interactive);

        let perf_cpu_clock = build_perf_cpu_clock_command(
            frequency,
            &callgraph,
            &perf_output,
            profiled_command.clone(),
        );
        prop_assert_eq!(perf_cpu_clock.program, "perf");
        prop_assert!(perf_cpu_clock.args.starts_with(&[
            "record".to_string(),
            "-e".to_string(),
            "cpu-clock".to_string(),
            "-F".to_string(),
            frequency.to_string(),
        ]));
        let expected_perf_cpu_clock_tail = [
            "-g".to_string(),
            "--call-graph".to_string(),
            callgraph.clone(),
            "-o".to_string(),
            perf_output.display().to_string(),
            "--".to_string(),
        ]
        .into_iter()
        .chain(profiled_command.clone())
        .collect::<Vec<_>>();
        prop_assert_eq!(
            &perf_cpu_clock.args[5..],
            expected_perf_cpu_clock_tail.as_slice()
        );
        prop_assert!(perf_cpu_clock.interactive);

        let bpftrace = build_bpftrace_offcpu_command(shell_command.clone(), duration_secs);
        prop_assert_eq!(bpftrace.program, "bpftrace");
        prop_assert_eq!(&bpftrace.args[0], "-e");
        prop_assert!(bpftrace.args[1].contains("sched:sched_switch"));
        let expected_interval = format!("interval:s:{duration_secs}");
        prop_assert!(bpftrace.args[1].contains(&expected_interval));
        prop_assert_eq!(
            &bpftrace.args[2..],
            ["-c", shell_command.as_str(), "--unsafe"]
        );
        prop_assert!(bpftrace.interactive);

        let xctrace_record = build_xctrace_record_command(&trace_path, &pid_file, profiled_command.clone());
        prop_assert_eq!(xctrace_record.program, "xctrace");
        let expected_xctrace_prefix = [
            "record".to_string(),
            "--quiet".to_string(),
            "--template".to_string(),
            "CPU Profiler".to_string(),
            "--output".to_string(),
            trace_path.display().to_string(),
            "--no-prompt".to_string(),
            "--launch".to_string(),
            "--".to_string(),
            "/bin/sh".to_string(),
            "-c".to_string(),
        ];
        prop_assert_eq!(
            &xctrace_record.args[..11],
            expected_xctrace_prefix.as_slice()
        );
        prop_assert!(xctrace_record
            .args
            .iter()
            .any(|arg| arg.contains("PYROCLAST_XCTRACE_TARGET_PID")));
        prop_assert_eq!(
            xctrace_record.env,
            vec![(
                "PYROCLAST_XCTRACE_TARGET_PID".to_string(),
                pid_file.display().to_string(),
            )]
        );
        prop_assert!(xctrace_record
            .args
            .ends_with(&profiled_command));
        prop_assert!(xctrace_record.interactive);

        let xctrace_export = build_xctrace_export_cpu_command(&trace_path, &xml_path);
        prop_assert_eq!(xctrace_export.program, "xctrace");
        prop_assert_eq!(
            xctrace_export.args,
            vec![
                "export".to_string(),
                "--input".to_string(),
                trace_path.display().to_string(),
                "--output".to_string(),
                xml_path.display().to_string(),
                "--xpath".to_string(),
                "//table".to_string(),
            ]
        );
        prop_assert!(!xctrace_export.interactive);
    }

    #[test]
    fn property_builds_batched_addr2line_command_for_generated_requests(
        path in string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,31}").expect("valid addr2line path regex"),
        addresses in prop::collection::vec(any::<u64>(), 0..8),
    ) {
        let path = PathBuf::from(path);
        let requests = addresses
            .iter()
            .map(|relative_address| SymbolRequest {
                path: path.clone(),
                relative_address: *relative_address,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            })
            .collect::<Vec<_>>();
        let mut expected_stdin = String::new();
        for address in &addresses {
            let _ = writeln!(expected_stdin, "0x{address:x}");
        }

        let command = build_addr2line_command(&path, &requests);
        let expected_args = vec![
            "-f".to_string(),
            "-C".to_string(),
            "-e".to_string(),
            path.to_string_lossy().into_owned(),
        ];

        prop_assert_eq!(command.program, "addr2line");
        prop_assert_eq!(command.args, expected_args);
        prop_assert_eq!(command.stdin, Some(expected_stdin.into_bytes()));
        prop_assert!(!command.interactive);
    }
}
