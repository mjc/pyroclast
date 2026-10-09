{
  description = "pyroclast CLI";

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
      packageDescription = "pyroclast CLI";
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
            src = pkgs.lib.cleanSourceWith {
              src = pkgs.lib.cleanSource ./.;
              filter =
                path: type:
                craneLib.filterCargoSources path type
                || pkgs.lib.any (suffix: pkgs.lib.hasSuffix suffix (toString path)) [
                  "/vendor/inferno/src/flamegraph/flamegraph.css"
                  "/vendor/inferno/src/flamegraph/flamegraph.js"
                ];
            };
            strictDeps = true;
          };
          cargoArtifacts = craneLib.buildDepsOnly (
            commonArgs
            // {
              pname = "pyroclast";
              version = "0.1.0";
              cargoExtraArgs = "--bins";
              doCheck = false;
            }
          );
          pyroclast = craneLib.buildPackage (
            commonArgs
            // {
              pname = "pyroclast";
              version = "0.1.0";
              inherit cargoArtifacts;
              cargoExtraArgs = "--bins";
              doCheck = false;
              meta = {
                description = packageDescription;
                mainProgram = "pyroclast";
              };
            }
          );
        in
        {
          default = pyroclast;
        }
        // pkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.isLinux || pkgs.stdenv.hostPlatform.isDarwin) {
          pyroclast-addr2line = pkgs.callPackage ./nix/binutils-provider.nix { };
        }
      );

      checks = forAllSystems (
        { pkgs, system }:
        {
          package-source-assets = pkgs.runCommand "pyroclast-package-source-assets" { } ''
            test -s ${self.packages.${system}.default.src}/vendor/inferno/src/flamegraph/flamegraph.css
            test -s ${self.packages.${system}.default.src}/vendor/inferno/src/flamegraph/flamegraph.js
            mkdir "$out"
          '';
        }
      );

      apps = forAllSystems (
        { system, ... }:
        {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/pyroclast";
            meta.description = packageDescription;
          };
          pyroclast = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/pyroclast";
            meta.description = packageDescription;
          };
        }
      );

    };
}
