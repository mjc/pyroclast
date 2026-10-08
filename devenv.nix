{ pkgs, lib, ... }:
{
  languages.rust = {
    enable = true;
    # The Darwin rust-overlay aggregate currently aliases lib directories,
    # causing its union builder to copy librustc_driver onto itself.
    channel = if pkgs.stdenv.hostPlatform.isDarwin then "nixpkgs" else "stable";
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

  scripts.check-perf-parity.exec = ''
    exec "$DEVENV_ROOT/scripts/check-perf-parity" "$@"
  '';

  scripts.xctrace = lib.mkIf pkgs.stdenv.hostPlatform.isDarwin {
    exec = ''
      # Keep Nix's SDK for compilation; only native profiling needs Xcode.
      export DEVELOPER_DIR=$(/usr/bin/env -u DEVELOPER_DIR /usr/bin/xcode-select -p)
      exec /usr/bin/xcrun xctrace "$@"
    '';
  };

  enterShell = ''
    "$DEVENV_ROOT/scripts/install-hooks"

    if [ "$(uname -s)" = Darwin ]; then
      if ! /usr/bin/env -u DEVELOPER_DIR /usr/bin/xcrun --find xctrace >/dev/null 2>&1; then
        echo "warning: xctrace not found; install Xcode for macOS profiling" >&2
      fi
    fi
  '';
}
