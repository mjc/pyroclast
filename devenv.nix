{ pkgs, lib, inputs, ... }:
let
  gnuProvider = pkgs.callPackage ./nix/binutils-provider.nix { };
in
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
    # Darwin rustup components ship lib as a symlink. lndir keeps that
    # symlink, so rust-overlay's librustc_driver copy hits the same file
    # and rust-std is never merged in. Rebuild lib from every component.
    toolchainPackage = lib.mkIf pkgs.stdenv.hostPlatform.isDarwin (lib.mkForce (
      ((pkgs.extend (import inputs.rust-overlay)).rust-bin.stable.latest.default.override {
        extensions = [ "rust-analyzer" ];
      }).overrideAttrs (old: {
        buildCommand =
          let
            anchor = "shopt nullglob";
            patched = lib.replaceStrings [ anchor ] [
              ''
                if [ -L "$out/lib" ]; then
                  rm "$out/lib"
                  mkdir "$out/lib"
                  merge_tree() {
                    local src="$1" dest="$2" entry name
                    mkdir -p "$dest"
                    for entry in "$src"/*; do
                      [ -e "$entry" ] || [ -L "$entry" ] || continue
                      name="''${entry##*/}"
                      if [ -d "$entry" ] && [ ! -L "$entry" ]; then
                        merge_tree "$entry" "$dest/$name"
                      elif [ ! -e "$dest/$name" ] && [ ! -L "$dest/$name" ]; then
                        ln -s "$entry" "$dest/$name"
                      fi
                    done
                  }
                  for component in "''${paths[@]}"; do
                    if [ -e "$component/lib" ] || [ -L "$component/lib" ]; then
                      merge_tree "$(realpath -e "$component/lib")" "$out/lib"
                    fi
                  done
                fi
                shopt nullglob
              ''
            ] old.buildCommand;
          in
          if patched == old.buildCommand then
            throw "rust-overlay Darwin join no longer contains '${anchor}'"
          else
            patched;
      })
    ));
  };

  packages =
    with pkgs;
    [
      cargo-nextest
      hyperfine
      inferno
      jq
      libxslt
      nixfmt
      shellcheck
      time
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
    )
    # Native regression tests exercise the explicit GNU backend; application
    # packages and all public symbolizer defaults remain in-process Rust.
    ++ lib.optional (pkgs.stdenv.isLinux || pkgs.stdenv.isDarwin) gnuProvider;

  env.RUST_BACKTRACE = "1";

  # Native tests must not mistake the Darwin compiler's LLVM addr2line for GNU.
  env.PYRO_GNU_ORACLE = "${gnuProvider.independentOracle}/bin/addr2line";

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
