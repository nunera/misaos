# Evaluation rejects unsafe stock-NixOS export declarations before activation.
{ nixpkgs, pkgs, system, strataModule, misa, strataFixture, strataDesktopFixture, planFixture }:

let
  lib = nixpkgs.lib;
  publisherKeys.synthetic-review = {
    publicKey = builtins.hashString "sha256" "misa strata module test publisher key";
    validFrom = 1704067200;
    validUntil = 1893456000;
  };
  instance = {
    plan = strataFixture;
    user = "alice";
    store = "/home/alice/.local/share/misa/roots";
    cliExports = [ "debian-hello" ];
    inherit publisherKeys;
  };
  evaluate = settings:
    lib.nixosSystem {
      inherit system;
      modules = [
        strataModule
        ({ ... }: {
          users.users.alice.isNormalUser = true;
          misa.strata.package = misa;
          misa.strata.instances = settings;
        })
      ];
    };
  fails = settings:
    let
      evaluated = evaluate settings;
    in !(builtins.tryEval (builtins.deepSeq
      (lib.mapAttrs (_: user: user.packages) evaluated.config.users.users) true)).success;
  cases = [
    (fails { test = instance // { cliExports = [ "missing" ]; }; })
    (fails { test = instance // { desktopExports = [ "debian-hello" ]; }; })
    (fails { test = instance // { publisherKeys = { }; }; })
    (fails { test = instance // { publisherKeys.synthetic-review = publisherKeys.synthetic-review // { validUntil = 1893456001; }; }; })
    (fails { test = instance // { publisherKeys.synthetic-review = publisherKeys.synthetic-review // { status = "revoked"; }; }; })
    (fails { test = instance // { store = "/srv/unowned"; }; })
    (fails { test = instance // { user = "root"; }; })
    (fails { test = instance // { plan = planFixture; }; })
    (fails { test = instance // { plan = "/home/alice/alterable.json"; }; })
    (fails { a = instance; b = instance; })
    (fails {
      a = instance // { plan = strataDesktopFixture; cliExports = [ ]; desktopExports = [ "debian-hello" ]; };
      b = instance // { plan = strataDesktopFixture; cliExports = [ ]; desktopExports = [ "debian-hello" ]; };
    })
  ];
  allRejected = lib.all (x: x) cases;
in
assert allRejected;
pkgs.runCommand "misa-strata-module-evaluation" { } ''
  mkdir -p "$out"
''
