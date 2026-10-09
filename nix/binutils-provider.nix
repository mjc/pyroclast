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
  nativeBase = binutils-unwrapped;
  base =
    if stdenv.hostPlatform.isDarwin then
      nativeBase.overrideAttrs (old: {
        configureFlags = old.configureFlags ++ provenance.darwinExtraConfigureFlags;
      })
    else
      nativeBase;
  expectedFlags =
    if stdenv.hostPlatform.isDarwin then provenance.darwinConfigureFlags else provenance.configureFlags;
  sourcePatches = map (path: {
    name = baseNameOf path;
    sha256 = builtins.hashFile "sha256" path;
  }) base.patches;
in
assert stdenv.hostPlatform.isLinux || stdenv.hostPlatform.isDarwin;
assert base.version == provenance.version;
assert base.src.outputHash == provenance.source.hash;
assert
  nativeBase.configureFlags == expectedFlags
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
    make MAKEINFO=true configure-binutils
    make -C binutils -j"$NIX_BUILD_CORES" MAKEINFO=true addr2line
    runHook postBuild
  '';
  doCheck = true;
  nativeCheckInputs = (old.nativeCheckInputs or [ ]) ++ [
    python3
    coreutils
  ];
  checkPhase = ''
    runHook preCheck
    if test ${
      lib.boolToString (stdenv.hostPlatform.isLinux && stdenv.hostPlatform.isx86_64)
    } = true; then
      # Scope build libraries to tracees, never the fixture compiler/assembler.
      PYRO_PROVIDER_LIBRARY_PATH="$PWD/bfd/.libs:$PWD/libsframe/.libs" \
        bash ${vendor}/tests/check-native.sh \
          "$PWD/binutils/.libs/addr2line" ${base}/bin/addr2line
    fi
    PYRO_PROVIDER_LIBRARY_PATH="$PWD/bfd/.libs:$PWD/libsframe/.libs" \
      bash ${vendor}/tests/check-portable.sh \
        "$PWD/binutils/.libs/addr2line" ${base}/bin/addr2line
    ${lib.optionalString stdenv.hostPlatform.isDarwin ''
      for target in x86_64-linux-gnu aarch64-linux-gnu; do
        PYRO_FIXTURE_CC=${stdenv.cc.cc}/bin/clang PYRO_FIXTURE_TARGET="$target" \
          PYRO_PROVIDER_LIBRARY_PATH="$PWD/bfd/.libs:$PWD/libsframe/.libs" \
          bash ${vendor}/tests/check-portable.sh \
            "$PWD/binutils/.libs/addr2line" ${base}/bin/addr2line
      done
    ''}
    source_dir=$(dirname "$configureScript")
    adapters=(portable)
    if test ${lib.boolToString stdenv.hostPlatform.isLinux} = true; then
      adapters=(linux portable)
    fi
    frame_flags=()
    if test -f libsframe/Makefile; then
      frame_flags=(-Llibsframe/.libs -lsframe)
    fi
    for adapter in "''${adapters[@]}"; do
      flags=()
      if test "$adapter" = portable; then
        flags=(-DPYRO_PORTABLE_SNAPSHOTS)
      fi
      $CC -g -O2 -Wall -Wextra -Werror "''${flags[@]}" \
        -Ibfd -Ibinutils -I"$source_dir/bfd" -I"$source_dir/binutils" -I"$source_dir/include" \
        ${vendor}/tests/api-proof.c -Lbfd/.libs -lbfd "''${frame_flags[@]}" \
        libiberty/libiberty.a -o "api-proof-$adapter"
      LD_LIBRARY_PATH="$PWD/bfd/.libs:$PWD/libsframe/.libs" \
        DYLD_LIBRARY_PATH="$PWD/bfd/.libs:$PWD/libsframe/.libs" \
        timeout --kill-after=1 4 "./api-proof-$adapter" \
          "$PWD/api.$adapter.primary" "$PWD/api.$adapter.auxiliary"
    done
    runHook postCheck
  '';
  installPhase = ''
    runHook preInstall
    if test -f libsframe/Makefile; then
      make -C libsframe install-libLTLIBRARIES
    fi
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
    if test ${
      lib.boolToString (stdenv.hostPlatform.isLinux && stdenv.hostPlatform.isx86_64)
    } = true; then
      env -u LD_LIBRARY_PATH bash ${vendor}/tests/check-native.sh \
        "$out/bin/pyroclast-addr2line" ${base}/bin/addr2line
    fi
    env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH bash ${vendor}/tests/check-portable.sh \
      "$out/bin/pyroclast-addr2line" ${base}/bin/addr2line
    ${lib.optionalString stdenv.hostPlatform.isDarwin ''
      for target in x86_64-linux-gnu aarch64-linux-gnu; do
        env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH \
          PYRO_FIXTURE_CC=${stdenv.cc.cc}/bin/clang PYRO_FIXTURE_TARGET="$target" \
          bash ${vendor}/tests/check-portable.sh \
            "$out/bin/pyroclast-addr2line" ${base}/bin/addr2line
      done
    ''}
  '';
  passthru = {
    independentOracle = base;
    inherit provenance;
  };
  meta = old.meta // {
    description = "Private GNU addr2line with retained read-only BFD input snapshots";
    longDescription = ''
      Separately named GNU addr2line for selected primary bytes and immutable
      auxiliary snapshots. Linux and Darwin adapters for explicit GNU batches;
      default application symbolization remains in-process Rust.
    '';
    mainProgram = "pyroclast-addr2line";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
})
