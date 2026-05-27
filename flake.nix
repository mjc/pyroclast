{
  description = "pyroclast CLI and development shell";

  inputs = {
    crane.url = "github:ipetkov/crane";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      crane,
      nixpkgs,
      ...
    }:
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
      packages = forAllSystems (
        { pkgs, ... }:
        let
          craneLib = crane.mkLib pkgs;
          commonArgs = {
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
          };
          cargoArtifacts = craneLib.buildDepsOnly (
            commonArgs
            // {
              pname = "pyroclast";
              version = "0.1.0";
              cargoExtraArgs = "--bin pyroclast";
              doCheck = false;
            }
          );
          pyroclast = craneLib.buildPackage (
            commonArgs
            // {
              pname = "pyroclast";
              version = "0.1.0";
              inherit cargoArtifacts;
              cargoExtraArgs = "--bin pyroclast";
              doCheck = false;
            }
          );
        in
        {
          default = pyroclast;
        }
      );

      apps = forAllSystems (
        { system, ... }:
        {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/pyroclast";
          };
          pyroclast = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/pyroclast";
          };
        }
      );

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
