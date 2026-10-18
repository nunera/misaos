# S1 acceptance on stock NixOS: one publisher-signed, Debian-derived OCI image with
# a CLI export and a real GUI export, launched through the actual `misa` launcher
# by an ordinary user in a real graphical session.
#
# Two NixOS VM tests share one guest layout:
#
#  1. `oracle` boots the guest and performs the real local admission and import of
#     the fixture images as the unprivileged user, returning the actual
#     `misa strata import` records (receipts and VerifiedRootRefs).
#  2. `accept` builds the immutable, validated strata plans from exactly those
#     records, activates the narrowly scoped NixOS module with them, and re-runs the
#     whole scenario from scratch: it must reproduce the same receipts, then proves
#     publisher qualification, launch, host-path denial, GUI, upgrade survival,
#     retention, disk-growth reporting and offline relaunch after reboot.
#
# Plan receipts are therefore not synthetic and the plan is not mutable at runtime:
# a drift between the two stages makes the acceptance test fail.
{ pkgs, misa, strataModule }:

let
  inherit (pkgs) lib;

  fixture = import ./s1-fixture.nix { inherit pkgs misa; };
  planLib = import ../../nix/lib.nix { getTool = _: misa; };

  store = "/home/alice/.local/share/misa/roots";
  share = "/home/alice/misa-s1-share";
  stratumNames = [ "debian-upstream" "debian-desktop-v1" "debian-desktop-v2" ];

  # Fixture publisher key window, UTC seconds (2023-11-14 .. 2100-01-01).
  validFrom = 1700000000;
  validUntil = 4102444800;

  # Identical for both stages: same uid, home, store path, disk and pinned toolchain.
  guest = {
    virtualisation = {
      memorySize = 3072;
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
    S1 = json.loads(${builtins.toJSON (builtins.toJSON data)})
  '';

  operator = {
    secret = "${fixture.keys}/operator/secret.json";
    public = "${fixture.keys}/operator/public.json";
  };

  # --- stage 1 ---------------------------------------------------------------
  oracle = pkgs.testers.runNixOSTest {
    name = "misa-s1-oracle";
    nodes.machine = { ... }: {
      imports = [ guest ];
      environment.systemPackages = [ misa ];
    };
    testScript =
      header { inherit store operator; inherit (fixture) locks layouts; }
      + builtins.readFile ./s1-lib.py
      + builtins.readFile ./s1-oracle.py;
  };

  expected = lib.genAttrs stratumNames
    (name: builtins.fromJSON (builtins.readFile "${oracle}/${name}.import.json"));

  # The oracle imported the images this evaluation signed and locked.
  sanity = lib.all (x: x) [
    (lib.assertMsg (expected.debian-upstream.verifiedRoot.digest == fixture.summary.base)
      "oracle imported a different upstream manifest than the pinned Debian base")
    (lib.assertMsg (expected.debian-desktop-v1.verifiedRoot.digest == fixture.summary.v1.digest)
      "oracle imported a different release-1 manifest than the fixture image")
    (lib.assertMsg (expected.debian-desktop-v2.verifiedRoot.digest == fixture.summary.v2.digest)
      "oracle imported a different release-2 manifest than the fixture image")
  ];

  # --- plans built from the actual receipts ---------------------------------
  fileDigest = path: "sha256:" + builtins.hashFile "sha256" path;
  rootOf = name: expected.${name}.verifiedRoot;

  publisherPolicy = [{
    alg = "ed25519";
    keyId = fixture.publisherKeyId;
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
    { id = "x11-socket"; kind = "directory"; source = "/tmp/.X11-unix"; target = "/tmp/.X11-unix"; writable = false; }
    { id = "xauthority"; kind = "file"; source = "/home/alice/.Xauthority"; target = "/tmp/.Xauthority"; writable = false; }
  ];

  probeExport = digest: {
    id = "debian-probe";
    name = "debian-probe";
    root = digest;
    program = "/usr/local/bin/misa-probe";
    argv = [ "misa-probe" ];
    env = runtimeEnv;
    grants = [ "share" ];
  };

  xclockExport = digest: {
    id = "debian-xclock";
    name = "debian-xclock";
    root = digest;
    program = "/usr/bin/xclock";
    argv = [ "xclock" "-title" "misa-s1-gui" ];
    env = runtimeEnv // { DISPLAY = ":0"; XAUTHORITY = "/tmp/.Xauthority"; };
    grants = [ "x11-socket" "xauthority" ];
    desktop = {
      id = "misa-s1-xclock.desktop";
      entryDigest = fixture.desktopEntryDigest;
      icons = [ ];
      mime = [ ];
      dbusName = null;
    };
  };

  mkPlan = name: { roots, exports, hostGrants }:
    assert sanity;
    planLib.mkStrataPlan {
      inherit pkgs name;
      declaration = {
        annotations = {
          fixture = "S1 VM test. The images are Debian-derived and signed by a fixture publisher key; the Debian project signed nothing here.";
          receipts = "Roots are the actual misa.import/v1 receipts returned by the oracle VM stage.";
        };
        inherit exports hostGrants roots;
        foreignStorage.mode = "retain-all";
        hostId = "misa-s1-vm";
        inputs = {
          flakeLockDigest = fileDigest ../../flake.lock;
          flakeSourceDigest = fileDigest ./s1.nix;
          # The launcher requires this to equal the admitted lock digest of the exported root.
          foreignLockDigest = expected.${(lib.findFirst (root: root.digest == (builtins.head exports).root) null roots).name}.receipt.lockDigest;
          misaLibraryDigest = fileDigest ../../nix/lib.nix;
        };
        requiredFeatures = [ ];
        trust = {
          approvers = { keys = [ ]; mode = "interactive"; threshold = 0; };
          channel = {
            rootDigest = "sha256:" + builtins.hashString "sha256" "misa-s1: no update channel is evaluated";
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

  v1 = rootOf "debian-desktop-v1";
  v2 = rootOf "debian-desktop-v2";
  upstream = rootOf "debian-upstream";

  planV1 = mkPlan "misa-s1-plan-v1" {
    roots = [ v1 ];
    exports = [ (probeExport v1.digest) (xclockExport v1.digest) ];
    hostGrants = grants;
  };
  # The upgrade: both retained roots, exports now selecting release 2.
  planV2 = mkPlan "misa-s1-plan-v2" {
    roots = [ v1 v2 ];
    exports = [ (probeExport v2.digest) (xclockExport v2.digest) ];
    hostGrants = grants;
  };
  # The unmodified Docker image: no publisher ever signed it.
  planUpstream = mkPlan "misa-s1-plan-upstream" {
    roots = [ upstream ];
    exports = [{
      id = "upstream-probe";
      name = "upstream-probe";
      root = upstream.digest;
      program = "/bin/cat";
      argv = [ "cat" "/etc/os-release" ];
      env = { HOME = "/tmp"; PATH = runtimeEnv.PATH; };
      grants = [ ];
    }];
    hostGrants = [ ];
  };

  publisherKeys = {
    ${fixture.publisherKeyId} = {
      publicKey = fixture.publisherPublicKey;
      inherit validFrom validUntil;
      status = "active";
    };
  };

  # --- stage 2 ---------------------------------------------------------------
  accept = pkgs.testers.runNixOSTest {
    name = "misa-s1-stock-nixos";
    nodes.machine = { pkgs, ... }: {
      imports = [ guest strataModule ];

      # Isolated guest: any registry access during the scenario would fail loudly.
      virtualisation.restrictNetwork = true;

      # Stock graphical session: lightdm autologin into IceWM for the ordinary user.
      services.xserver.enable = true;
      services.xserver.displayManager.lightdm.enable = true;
      services.displayManager.autoLogin = { enable = true; user = "alice"; };
      services.displayManager.defaultSession = "none+icewm";
      services.xserver.windowManager.icewm.enable = true;

      environment.systemPackages = with pkgs; [ glib xauth xhost xprop xwininfo ];
      environment.etc."misa-s1-host-canary".text = "host-only\n";
      systemd.tmpfiles.rules = [ "d ${share} 0700 alice users -" ];

      misa.strata.package = misa;
      misa.strata.instances = {
        fixture = {
          plan = planV1;
          user = "alice";
          inherit store publisherKeys;
          cliExports = [ "debian-probe" ];
          desktopExports = [ "debian-xclock" ];
        };
        upstream = {
          plan = planUpstream;
          user = "alice";
          inherit store publisherKeys;
          cliExports = [ "upstream-probe" ];
        };
      };

      # The declared upgrade: same module, the release-2 plan.
      specialisation.upgraded.configuration = { lib, ... }: {
        misa.strata.instances.fixture.plan = lib.mkForce planV2;
      };
    };
    testScript =
      header {
        inherit store operator expected;
        inherit (fixture) locks layouts;
        misa = "${misa}";
        publisher = { keyId = fixture.publisherKeyId; publicKey = fixture.publisherPublicKey; };
        statements = {
          v1 = "${fixture.statements}/v1.json";
          v2 = "${fixture.statements}/v2.json";
          rogueV1 = "${fixture.statements}/rogue-v1.json";
        };
        plans = {
          v1 = "${planV1}/strata.json";
          v2 = "${planV2}/strata.json";
          upstream = "${planUpstream}/strata.json";
        };
      }
      + builtins.readFile ./s1-lib.py
      + builtins.readFile ./s1-accept.py;
  };
in
accept
