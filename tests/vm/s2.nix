# S2 acceptance on stock NixOS: a second foreign ecosystem with its own ABI. A
# publisher-signed, Void-musl-derived OCI image joins the S1 Debian-derived image in
# one merged lockset and one strata plan, launched through the real `misa` launcher
# by an ordinary user.
#
# Two NixOS VM tests share one guest layout, as in S1:
#
#  1. `oracle` performs the real local admission and imports as the unprivileged
#     user: first the Debian root under its own S1 lock (the previously imported
#     state), then all three roots of the merged lockset.
#  2. `accept` builds immutable plans from exactly those receipts, boots with the
#     Debian-only plan, grows the lockset, activates the two-ecosystem plan, and
#     proves distinct package databases, the musl loader, the typed cross-libc
#     refusal, host isolation, retention and offline relaunch after reboot.
{ pkgs, misa, strataModule }:

let
  inherit (pkgs) lib;

  s1 = import ./s1-fixture.nix { inherit pkgs misa; };
  fixture = import ./s2-fixture.nix { inherit pkgs misa s1; };
  planLib = import ../../nix/lib.nix { getTool = _: misa; };

  store = "/home/alice/.local/share/misa/roots";
  share = "/home/alice/misa-s1-share";
  records = [ "single-debian" "lockset-debian" "lockset-void" "lockset-upstream" ];

  # Fixture publisher key window, UTC seconds (2023-11-14 .. 2100-01-01).
  validFrom = 1700000000;
  validUntil = 4102444800;

  guest = {
    virtualisation = {
      memorySize = 2048;
      cores = 2;
      diskSize = 6144;
    };
    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      description = "Alice";
    };
  };

  header = data: ''
    import json
    S2 = json.loads(${builtins.toJSON (builtins.toJSON data)})
    FIXTURE = S2
  '';

  operator = {
    secret = "${s1.keys}/operator/secret.json";
    public = "${s1.keys}/operator/public.json";
  };

  # --- stage 1 ---------------------------------------------------------------
  oracle = pkgs.testers.runNixOSTest {
    name = "misa-s2-oracle";
    nodes.machine = { ... }: {
      imports = [ guest ];
      environment.systemPackages = [ misa ];
    };
    testScript =
      header { inherit store operator; inherit (fixture) locks layouts; }
      + builtins.readFile ./s1-lib.py
      + builtins.readFile ./s2-lib.py
      + builtins.readFile ./s2-oracle.py;
  };

  expected = lib.genAttrs records
    (name: builtins.fromJSON (builtins.readFile "${oracle}/${name}.import.json"));

  # The oracle imported the images this evaluation built, locked and merged.
  sanity = lib.all (x: x) [
    (lib.assertMsg (expected.single-debian.verifiedRoot.digest == s1.summary.v1.digest)
      "oracle imported a different Debian manifest than the S1 release-1 image")
    (lib.assertMsg (expected.lockset-debian.verifiedRoot.digest == s1.summary.v1.digest)
      "the lockset's Debian entry is not the S1 release-1 image")
    (lib.assertMsg (expected.lockset-void.verifiedRoot.digest == fixture.summary.v1.digest)
      "oracle imported a different Void manifest than the fixture image")
    (lib.assertMsg (expected.lockset-upstream.verifiedRoot.digest == fixture.summary.base)
      "oracle imported a different upstream manifest than the pinned Void base")
    (lib.assertMsg (expected.lockset-void.verifiedRoot.libcFamily == "musl")
      "the Void root is not declared musl")
  ];

  # --- plans built from the actual receipts ---------------------------------
  fileDigest = path: "sha256:" + builtins.hashFile "sha256" path;

  publisherPolicy = [{
    alg = "ed25519";
    keyId = s1.publisherKeyId;
    status = "active";
    inherit validFrom validUntil;
  }];

  runtimeEnv = {
    HOME = "/tmp";
    LANG = "C.UTF-8";
    PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
  };

  grants = [
    { id = "share"; kind = "directory"; source = share; target = "/mnt/share"; writable = true; }
  ];

  exportFor = root: id: program: argv: extra: {
    inherit id program argv;
    name = id;
    root = root.digest;
    env = runtimeEnv;
    grants = [ ];
  } // extra;

  probeExport = root: id: exportFor root id "/usr/local/bin/misa-probe" [ "misa-probe" ] { grants = [ "share" ]; };
  # Each root's own package manager, reading only its own database.
  dpkgExport = root: exportFor root "debian-packages" "/usr/bin/dpkg-query"
    [ "dpkg-query" "--show" "--showformat=\${Package} \${Version}\\n" ] { };
  xbpsExport = root: exportFor root "void-packages" "/usr/bin/xbps-query" [ "xbps-query" "--list-pkgs" ] { };

  mkPlan = name: { roots, exports, lockRecord }:
    assert sanity;
    planLib.mkStrataPlan {
      inherit pkgs name;
      declaration = {
        annotations = {
          fixture = "S2 VM test. The images are Debian- and Void-derived and signed by a fixture publisher key; neither project signed anything here.";
          receipts = "Roots are the actual misa.import/v1 receipts returned by the oracle VM stage.";
        };
        roots = lib.sort (a: b: a.name < b.name) roots;
        exports = lib.sort (a: b: a.id < b.id) exports;
        hostGrants = grants;
        foreignStorage.mode = "retain-all";
        hostId = "misa-s2-vm";
        inputs = {
          flakeLockDigest = fileDigest ../../flake.lock;
          flakeSourceDigest = fileDigest ./s2.nix;
          # One plan binds exactly one admitted lock; multi-root plans use a merged lockset.
          foreignLockDigest = lockRecord.receipt.lockDigest;
          misaLibraryDigest = fileDigest ../../nix/lib.nix;
        };
        requiredFeatures = [ ];
        trust = {
          approvers = { keys = [ ]; mode = "interactive"; threshold = 0; };
          channel = {
            rootDigest = "sha256:" + builtins.hashString "sha256" "misa-s2: no update channel is evaluated";
            rootVersion = 1;
            thresholds = { root = 1; targets = 1; snapshot = 1; timestamp = 1; };
          };
          epoch = 1;
          imagePublishers = lib.genAttrs (map (root: root.sourceLockKey) roots) (_: publisherPolicy);
          nixSubstituters = [ ];
          repoKeys = { };
          time = { floorEpoch = validFrom; source = "rtc+bounded-ntp"; };
        };
      };
    };

  single = expected.single-debian.verifiedRoot;
  debian = expected.lockset-debian.verifiedRoot;
  void = expected.lockset-void.verifiedRoot;
  upstream = expected.lockset-upstream.verifiedRoot;

  # The S1 state: the Debian root under its own lock.
  planDebian = mkPlan "misa-s2-plan-debian" {
    roots = [ single ];
    exports = [ (probeExport single "debian-probe") (dpkgExport single) ];
    lockRecord = expected.single-debian;
  };
  # The grown lockset: both ecosystems behind one plan and one admitted lock.
  planLockset = mkPlan "misa-s2-plan-lockset" {
    roots = [ debian void upstream ];
    exports = [
      (probeExport debian "debian-probe")
      (dpkgExport debian)
      (probeExport void "void-probe")
      (xbpsExport void)
      (exportFor void "void-glibc-true" "/usr/local/bin/glibc-true" [ "glibc-true" ] { })
      (exportFor upstream "void-upstream" "/usr/bin/cat" [ "cat" "/etc/os-release" ] { })
    ];
    lockRecord = expected.lockset-void;
  };
  locksetExports = [ "debian-packages" "debian-probe" "void-glibc-true" "void-packages" "void-probe" "void-upstream" ];

  publisherKeys = {
    ${s1.publisherKeyId} = {
      publicKey = s1.publisherPublicKey;
      inherit validFrom validUntil;
      status = "active";
    };
  };

  # --- stage 2 ---------------------------------------------------------------
  accept = pkgs.testers.runNixOSTest {
    name = "misa-s2-stock-nixos";
    nodes.machine = { ... }: {
      imports = [ guest strataModule ];

      # Isolated guest: any registry access during the scenario would fail loudly.
      virtualisation.restrictNetwork = true;

      systemd.tmpfiles.rules = [ "d ${share} 0700 alice users -" ];

      misa.strata.package = misa;
      misa.strata.instances.fixture = {
        plan = planDebian;
        user = "alice";
        inherit store publisherKeys;
        cliExports = [ "debian-packages" "debian-probe" ];
      };

      # The declared lockset growth: same module, the two-ecosystem plan.
      specialisation.lockset.configuration = { lib, ... }: {
        misa.strata.instances.fixture = {
          plan = lib.mkForce planLockset;
          cliExports = lib.mkForce locksetExports;
        };
      };
    };
    testScript =
      header {
        inherit store operator expected;
        inherit (fixture) locks layouts;
        packages = fixture.summary.packages;
        statements = {
          debian = "${s1.statements}/v1.json";
          void = "${fixture.statements}/void-v1.json";
        };
        plans = {
          debian = "${planDebian}/strata.json";
          lockset = "${planLockset}/strata.json";
        };
      }
      + builtins.readFile ./s1-lib.py
      + builtins.readFile ./s2-lib.py
      + builtins.readFile ./s2-accept.py;
  };
in
accept
