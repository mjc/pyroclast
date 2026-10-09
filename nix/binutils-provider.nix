{
  lib,
  stdenv,
  binutils-unwrapped,
  python3,
  coreutils,
}:
let
  vendor = ../vendor/binutils-provider;
  provenance = builtins.fromJSON (builtins.readFile (vendor + "/provenance.json"));
  base = binutils-unwrapped;
  sourcePatches = map (path: {
    name = baseNameOf path;
    sha256 = builtins.hashFile "sha256" path;
  }) base.patches;
in
assert stdenv.hostPlatform.isLinux;
assert base.version == provenance.version;
assert base.src.outputHash == provenance.source.hash;
assert
  base.configureFlags == provenance.configureFlags
  ++ [
    "--build=${stdenv.buildPlatform.config}"
    "--host=${stdenv.hostPlatform.config}"
    "--target=${stdenv.targetPlatform.config}"
  ];
assert sourcePatches == provenance.nixPatches;
assert builtins.hashFile "sha256" (vendor + "/provider.patch") == provenance.providerPatchSha256;
base.overrideAttrs (old: {
  pname = "pyroclast-addr2line";
  outputs = [ "out" ];
  patches = old.patches ++ [ (vendor + "/provider.patch") ];
  # Keep GNU's original configured global discovery root, not the private libdir.
  configureFlags = old.configureFlags ++ [
    "--with-separate-debug-dir=${lib.getLib base}/lib/debug"
  ];
  buildPhase = ''
    runHook preBuild
    make -j"$NIX_BUILD_CORES" MAKEINFO=true all-libiberty all-bfd all-opcodes
    make -j"$NIX_BUILD_CORES" MAKEINFO=true all-binutils
    runHook postBuild
  '';
  doCheck = stdenv.hostPlatform.isx86_64;
  nativeCheckInputs = (old.nativeCheckInputs or [ ]) ++ [
    python3
    coreutils
  ];
  checkPhase = ''
    runHook preCheck
    # Scope build libraries to tracees, never the fixture compiler/assembler.
    PYRO_PROVIDER_LIBRARY_PATH="$PWD/bfd/.libs:$PWD/libsframe/.libs" \
      bash ${vendor}/tests/check-native.sh \
        "$PWD/binutils/.libs/addr2line" ${base}/bin/addr2line
    source_dir=$(dirname "$configureScript")
    for adapter in linux portable; do
      flags=()
      if test "$adapter" = portable; then
        flags=(-DPYRO_PORTABLE_SNAPSHOTS)
      fi
      $CC -g -O2 -Wall -Wextra -Werror "''${flags[@]}" \
        -Ibfd -Ibinutils -I"$source_dir/bfd" -I"$source_dir/binutils" -I"$source_dir/include" \
        ${vendor}/tests/api-proof.c -Lbfd/.libs -lbfd -Llibsframe/.libs -lsframe \
        libiberty/libiberty.a -o "api-proof-$adapter"
      LD_LIBRARY_PATH="$PWD/bfd/.libs:$PWD/libsframe/.libs" \
        timeout --kill-after=1 4 "./api-proof-$adapter" \
          "$PWD/api.$adapter.primary" "$PWD/api.$adapter.auxiliary"
    done
    runHook postCheck
  '';
  installPhase = ''
    runHook preInstall
    make -C libsframe install-libLTLIBRARIES
    make -C bfd install-bfdlibLTLIBRARIES
    make -C binutils install-binPROGRAMS bin_PROGRAMS=addr2line
    mv "$out/bin/addr2line" "$out/bin/pyroclast-addr2line"
    mkdir -p "$out/share/doc/pyroclast-addr2line"
    cp -r ${vendor}/licenses "$out/share/doc/pyroclast-addr2line/"
    cp ${vendor}/provenance.json ${vendor}/provider.patch \
      "$out/share/doc/pyroclast-addr2line/"
    runHook postInstall
  '';
  postInstall = "";
  doInstallCheck = true;
  installCheckPhase = ''
    test -x "$out/bin/pyroclast-addr2line"
    test ! -e "$out/bin/addr2line"
    "$out/bin/pyroclast-addr2line" --version
    if test ${lib.boolToString stdenv.hostPlatform.isx86_64} = true; then
      env -u LD_LIBRARY_PATH bash ${vendor}/tests/check-native.sh \
        "$out/bin/pyroclast-addr2line" ${base}/bin/addr2line
    fi
  '';
  passthru = {
    independentOracle = base;
    inherit provenance;
  };
  meta = old.meta // {
    description = "Private GNU addr2line with immutable Linux BFD input snapshots";
    longDescription = ''
      Separately named GNU addr2line for selected primary bytes and immutable
      auxiliary snapshots. Linux memfd/procfs adapter for explicit GNU batches;
      default application symbolization remains in-process Rust.
    '';
    mainProgram = "pyroclast-addr2line";
    platforms = lib.platforms.linux;
  };
})
