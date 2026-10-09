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
        {
          default = import ./nix/pyroclast.nix { inherit pkgs crane; };
        }
        // pkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.isLinux || pkgs.stdenv.hostPlatform.isDarwin) {
          pyroclast-addr2line = pkgs.callPackage ./nix/binutils-provider.nix { };
        }
      );

      checks = forAllSystems (
        { pkgs, system }:
        let
          callPackagePyroclast = pkgs.callPackage ./nix/pyroclast.nix {
            inherit crane;
            src = ./.;
          };
        in
        {
          package-callpackage-interface =
            assert callPackagePyroclast.drvPath == self.packages.${system}.default.drvPath;
            pkgs.runCommand "pyroclast-callpackage-interface" { } ''
              mkdir "$out"
            '';
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
