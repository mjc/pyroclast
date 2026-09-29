{ pkgs, lib, ... }:
{
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [
      "cargo"
      "clippy"
      "rust-analyzer"
      "rustc"
      "rustfmt"
    ];
  };

  packages =
    with pkgs;
    [
      cargo-nextest
      hyperfine
      inferno
      jq
      nixfmt
      shellcheck
      tokio-console
    ]
    ++ lib.optionals pkgs.stdenv.isLinux (
      with pkgs;
      [
        binutils
        bpftrace
        elfutils
        heaptrack
        perf
        strace
        valgrind
      ]
    );

  env.RUST_BACKTRACE = "1";

  enterShell = ''
    git config --local core.hooksPath .githooks

    if [ "$(uname -s)" = Darwin ] && ! command -v xctrace >/dev/null 2>&1; then
      echo "warning: xctrace not found; install Xcode or Command Line Tools for macOS profiling" >&2
    fi
  '';
}
