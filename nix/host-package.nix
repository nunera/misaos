{ lib, rustPlatform }:
# Programs that run on a Misa-owned host: misa-handoff (PID 1 before the init),
# misa-svcrun (every service), misa-service (graph compiler, build time) and
# misa-activate (boot-entry publisher). Kept apart from `misa`, whose wrappers
# carry the OCI import tools into its closure.
rustPlatform.buildRustPackage {
  pname = "misa-host";
  version = "0.1.0";
  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let name = baseNameOf path;
      in lib.cleanSourceFilter path type
        && !(builtins.elem name [ "target" ".direnv" "result" ])
        && !(lib.hasPrefix "result-" name)
        # Harness and Nix edits must not rebuild the programs under test.
        && !(builtins.elem (toString path) [ (toString ../tests) (toString ../nix) ]);
  };
  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [ "--package" "misa-service" "--package" "misa-init" "--package" "misa-activate" ];
  cargoTestFlags = [ "--package" "misa-service" "--package" "misa-init" "--package" "misa-activate" ];

  meta = {
    description = "MisaOS owned-host boot handoff, service launcher, graph compiler and boot publisher";
    platforms = lib.platforms.linux;
  };
}
