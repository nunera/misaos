{ lib, rustPlatform, makeWrapper, skopeo, umoci, bubblewrap }:
rustPlatform.buildRustPackage {
  pname = "misa-cli";
  version = "0.1.0";
  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let name = baseNameOf path;
      in lib.cleanSourceFilter path type
        && !(builtins.elem name [ "target" ".direnv" "result" ])
        && !(lib.hasPrefix "result-" name);
  };
  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [ "--package" "misa-cli" "--bins" ];
  cargoTestFlags = [ "--workspace" ];
  nativeBuildInputs = [ makeWrapper ];
  postInstall = ''
    wrapProgram "$out/bin/misa" \
      --set MISA_SKOPEO "${skopeo}/bin/skopeo" \
      --set MISA_UMOCI "${umoci}/bin/umoci" \
      --set MISA_BWRAP "${bubblewrap}/bin/bwrap"
  '';

  meta = {
    description = "MisaOS strict plans and locally approved retained OCI roots";
    mainProgram = "misa";
    platforms = lib.platforms.linux;
  };
}
