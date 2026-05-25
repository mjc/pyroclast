use crate::process::CommandSpec;

#[must_use]
pub fn build_bpftrace_offcpu_command(profiled_command: String, duration_secs: u32) -> CommandSpec {
    CommandSpec::new("bpftrace")
        .arg("-e")
        .arg(offcpu_bpftrace_program(duration_secs))
        .arg("-c")
        .arg(profiled_command)
        .arg("--unsafe")
}

fn offcpu_bpftrace_program(duration_secs: u32) -> String {
    format!(
        r"
tracepoint:sched:sched_switch
{{
  if (args->prev_state != 0) {{
    @start[args->prev_pid] = nsecs;
  }}
  if (@start[args->next_pid]) {{
    @offcpu[kstack] = sum(nsecs - @start[args->next_pid]);
    delete(@start[args->next_pid]);
  }}
}}

interval:s:{duration_secs}
{{
  exit();
}}
"
    )
}
