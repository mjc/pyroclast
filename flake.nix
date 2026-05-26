{
  description = "pyroclast development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs { inherit system; };
          }
        );
    in
    {
      devShells = forAllSystems (
        { pkgs, ... }:
        let
          commonTools = with pkgs; [
            cargo
            cargo-nextest
            clippy
            hyperfine
            inferno
            jq
            nixfmt
            rustc
            rust-analyzer
            rustfmt
            shellcheck
            tokio-console
          ];
          linuxTools = with pkgs; [
            binutils
            bpftrace
            elfutils
            heaptrack
            perf
            strace
            valgrind
          ];
        in
        {
          default = pkgs.mkShell {
            packages = commonTools ++ pkgs.lib.optionals pkgs.stdenv.isLinux linuxTools;

            RUST_BACKTRACE = "1";

            shellHook = ''
              git config --local core.hooksPath .githooks

              if [ "$(uname -s)" = Darwin ] && ! command -v xctrace >/dev/null 2>&1; then
                echo "warning: xctrace not found; install Xcode or Command Line Tools for macOS profiling" >&2
              fi
            '';
          };
        }
      );
    };
}
