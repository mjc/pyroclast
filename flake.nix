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
                  "/LICENSE-APACHE"
                  "/LICENSE-MIT"
                  "/vendor/inferno/LICENSE"
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
              postInstall = ''
                mkdir -p "$out/share/doc/pyroclast/vendor/addr2line" "$out/share/doc/pyroclast/vendor/inferno"
                install -m644 LICENSE-APACHE LICENSE-MIT "$out/share/doc/pyroclast/"
                install -m644 vendor/addr2line/LICENSE-APACHE vendor/addr2line/LICENSE-MIT \
                  "$out/share/doc/pyroclast/vendor/addr2line/"
                install -m644 vendor/inferno/LICENSE "$out/share/doc/pyroclast/vendor/inferno/"
              '';
              meta = {
                description = packageDescription;
                mainProgram = "pyroclast";
                license = with pkgs.lib.licenses; [
                  asl20
                  mit
                ];
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
            for file in LICENSE-APACHE LICENSE-MIT vendor/addr2line/LICENSE-APACHE vendor/addr2line/LICENSE-MIT vendor/inferno/LICENSE; do
              test -s ${self.packages.${system}.default.src}/"$file"
            done
            mkdir "$out"
          '';
          package-license-files = pkgs.runCommand "pyroclast-package-license-files" { } ''
            for file in LICENSE-APACHE LICENSE-MIT vendor/addr2line/LICENSE-APACHE vendor/addr2line/LICENSE-MIT vendor/inferno/LICENSE; do
              cmp ${self.packages.${system}.default.src}/"$file" \
                ${self.packages.${system}.default}/share/doc/pyroclast/"$file"
            done
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
