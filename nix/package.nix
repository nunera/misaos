{ lib, rustPlatform }:
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
  cargoBuildFlags = [ "--package" "misa-cli" "--bin" "misa-plan" ];
  cargoTestFlags = [ "--workspace" ];

  meta = {
    description = "Strict schema-only MisaOS plan and generation validator";
    mainProgram = "misa-plan";
    platforms = lib.platforms.linux;
  };
}
