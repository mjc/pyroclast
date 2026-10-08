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
            src = craneLib.cleanCargoSource ./.;
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
