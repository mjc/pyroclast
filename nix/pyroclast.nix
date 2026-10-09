{
  pkgs,
  crane,
  src ? ../.,
}:
let
  craneLib = crane.mkLib pkgs;
  packageDescription = "pyroclast CLI";
  commonArgs = {
    src = pkgs.lib.cleanSourceWith {
      src = pkgs.lib.cleanSource src;
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
in
craneLib.buildPackage (
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
)
