# Build products of one host generation: the portable graph, its compiled Dinit tree,
# the borrowed stage 1, the top-level closure, the misa.plan/v1 record and the
# misa.generation/v1 manifest whose ID the boot entry names.
{ lib, config, pkgs, misaHost, misaTool, planLib, ... }:
let
  cfg = config.misa;
  inherit (cfg.kernel.packages) kernel;
  dinit = pkgs.dinit;
  sorted = lib.sort (a: b: a < b);

  node = id: s:
    let
      common = {
        inherit id;
        inherit (s) kind;
        scope.kind = "system";
        requires = sorted s.requires;
        wants = sorted s.wants;
        after = sorted s.after;
        requiredFeatures = [ ];
      };
    in
    if s.kind == "milestone" then common
    else
      assert lib.assertMsg (s.command != null) "misa.services.${id}: a ${s.kind} needs a command";
      common // {
        inherit (s) command argv cwd readiness restart stop;
        env = lib.mapAttrs (_: value: { kind = "literal"; inherit value; }) s.env;
        identity = { inherit (s.identity) uid gid; };
        directories = lib.sort (a: b: a.path < b.path) s.directories;
        sockets = [ ];
        capabilities = [ ];
      };

  graph = {
    services = map (id: node id cfg.services.${id}) (sorted (lib.attrNames cfg.services));
    targets = lib.mapAttrs (_: sorted) cfg.targets;
  };
  graphFile = pkgs.writeText "misa-${cfg.hostId}-graph.json" (builtins.toJSON graph);

  initTree = pkgs.runCommand "misa-${cfg.hostId}-dinit-tree"
    {
      outputs = [ "out" "specs" ];
      nativeBuildInputs = [ misaHost ];
    } ''
    misa-service compile --graph ${graphFile} --adapter dinit --release ${dinit.version} \
      --svcrun ${misaHost}/bin/misa-svcrun --tree-out "$out" --specs-out "$specs"
  '';

  etc = pkgs.runCommand "misa-${cfg.hostId}-etc" { } (''
    mkdir -p "$out"
    ln -s /proc/self/mounts "$out/mtab"
  '' + lib.concatStrings (lib.mapAttrsToList (path: text: ''
    mkdir -p "$(dirname "$out/${path}")"
    cp ${pkgs.writeText "etc-${baseNameOf path}" text} "$out/${path}"
  '') cfg.environment.etc));

  sw = pkgs.buildEnv {
    name = "misa-${cfg.hostId}-sw";
    paths = cfg.environment.packages;
    pathsToLink = [ "/bin" "/sbin" ];
  };

  firmware = pkgs.runCommand "misa-firmware-none" { } "mkdir -p $out/lib/firmware";

  stage1 = import ./stage1/${cfg.boot.stage1}.nix { inherit pkgs lib kernel cfg; };
  kernelImage = "${kernel}/${pkgs.stdenv.hostPlatform.linux-kernel.target}";

  toplevel = pkgs.runCommand "misa-host-${cfg.hostId}" { } ''
    mkdir "$out"
    ln -s ${misaHost}/bin/misa-handoff "$out/init"
    ln -s ${initTree} "$out/init-tree"
    ln -s ${initTree.specs} "$out/init-specs"
    ln -s ${etc} "$out/etc"
    ln -s ${sw} "$out/sw"
    ln -s ${kernel.modules} "$out/kernel-modules"
    ln -s ${firmware}/lib/firmware "$out/firmware"
    ln -s ${kernelImage} "$out/kernel"
    ln -s ${stage1.initrd}/initrd "$out/initrd"
  '';

  selector = cfg.boot.root.selector;
  bootPolicy = {
    cmdline.template =
      [ "misa.root=${selector.kind}=${selector.value}" ] ++ cfg.boot.cmdline ++ stage1.cmdline toplevel;
    inherit (cfg.boot) health publisher;
    root = {
      selector = { inherit (selector) kind value; };
      inherit (cfg.boot.root) fstype;
      mountFlags = sorted cfg.boot.root.mountFlags;
    };
    unlock = {
      method = "none";
      luksUuid = null;
      mapperName = null;
      tries = 0;
      timeoutSec = 0;
      allowDiscards = false;
    };
  };

  plan = planLib.mkHostPlan {
    inherit pkgs;
    name = "misa-${cfg.hostId}-plan";
    declaration = {
      inherit (cfg) hostId machineId inputs;
      annotations = cfg.annotations // {
        stage1 = stage1.description;
      } // lib.optionalAttrs (stage1.warnings != [ ]) {
        stage1-upstream-warning = lib.concatStringsSep " " stage1.warnings;
      };
      roots = [ ];
      exports = [ ];
      foreignStorage.mode = "retain-all";
      requiredFeatures = [ ];
      target = {
        system = pkgs.stdenv.hostPlatform.system;
        kernelArch = pkgs.stdenv.hostPlatform.parsed.cpu.name;
        rootFs = { inherit (selector) kind value; };
      };
      host = {
        topLevel = "${toplevel}";
        initrd = "${stage1.initrd}";
        kernel = "${kernel}";
        firmware = [ ];
        initAdapter = "dinit";
      };
      boot = bootPolicy;
      serviceGraph = graph;
      providers = [ ];
      mounts = [ ];
      users = [ ];
      volumes = [ ];
      trust = {
        approvers = { keys = [ ]; mode = "interactive"; threshold = 0; };
        channel = {
          rootDigest = "sha256:" + builtins.hashString "sha256" "misa-${cfg.hostId}: no update channel is evaluated";
          rootVersion = 1;
          thresholds = { root = 1; targets = 1; snapshot = 1; timestamp = 1; };
        };
        epoch = 1;
        imagePublishers = { };
        nixSubstituters = [ ];
        repoKeys = { };
        time = { floorEpoch = 1767225600; source = "rtc+bounded-ntp"; };
      };
    };
  };

  # Manifest of this generation. `patches` (JSON pointer = JSON value) change the body
  # before its ID is computed and `init` replaces the pinned init; only negative boot
  # fixtures use them.
  mkGeneration = { name ? "misa-${cfg.hostId}-generation", patches ? [ ], init ? "${dinit}/bin/dinit" }:
    pkgs.runCommand name { nativeBuildInputs = [ pkgs.python3 ]; } ''
      python3 ${./generation.py} \
        --plan ${plan}/plan.json --plan-digest ${plan}/digest.txt \
        --kernel-image ${kernelImage} --kernel-uname ${kernel.modDirVersion} \
        --modules-dir ${kernel.modules}/lib/modules \
        --initrd ${stage1.initrd}/initrd \
        --initrd-build-id sha256:${builtins.hashString "sha256" (builtins.unsafeDiscardStringContext stage1.initrd.drvPath)} \
        --module-order ${stage1.modules}/order \
        --init ${init} --tree ${initTree}/tree.json \
        --firmware-dir ${firmware}/lib/firmware \
        --misa-plan ${misaTool}/bin/misa-plan \
        ${lib.concatMapStrings (p: "--patch ${lib.escapeShellArg p} ") patches} \
        --out "$out"
    '';
in
{
  config.misa.build = {
    inherit graph graphFile initTree etc sw toplevel stage1 plan mkGeneration;
    generation = mkGeneration { };
  };
}
