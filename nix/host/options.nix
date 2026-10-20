# The full-host `misa.*` option namespace. It is evaluated with lib.evalModules on
# its own: NixOS modules do not apply, and an unknown option is an evaluation error
# naming it (the fail-closed rule of the module-mapping classes in Chapter 8).
{ lib, config, pkgs, ... }:
let
  inherit (lib) mkOption types;
  id = types.strMatching "[a-z][a-z0-9.-]*";
  selector = types.submodule {
    options = {
      kind = mkOption { type = types.enum [ "partuuid" "fsuuid" ]; };
      value = mkOption { type = types.strMatching "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"; };
    };
  };
  identity = types.submodule {
    options = {
      uid = mkOption { type = types.ints.unsigned; default = 0; };
      gid = mkOption { type = types.ints.unsigned; default = 0; };
    };
  };
  service = types.submodule ({ name, ... }: {
    options = {
      kind = mkOption { type = types.enum [ "longrun" "oneshot" "milestone" ]; };
      requires = mkOption { type = types.listOf id; default = [ ]; };
      wants = mkOption { type = types.listOf id; default = [ ]; };
      after = mkOption { type = types.listOf id; default = [ ]; };
      command = mkOption { type = types.nullOr types.str; default = null; };
      argv = mkOption { type = types.listOf types.str; default = [ ]; };
      cwd = mkOption { type = types.str; default = "/"; };
      env = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = "Literal environment; secrets are not supported yet.";
      };
      identity = mkOption { type = identity; default = { }; };
      readiness = mkOption { type = types.attrs; default = { kind = "exec-started"; }; };
      restart = mkOption { type = types.attrs; default = { kind = "never"; }; };
      stop = mkOption {
        type = types.attrs;
        default = { signal = "SIGTERM"; gracePeriod = 10; killProcessGroup = true; };
      };
      directories = mkOption { type = types.listOf types.attrs; default = [ ]; };
    };
  });
in
{
  options.misa = {
    hostId = mkOption { type = id; };
    machineId = mkOption { type = types.strMatching "[0-9a-f]{32}"; };
    inputs = mkOption {
      type = types.submodule {
        options = lib.genAttrs
          [ "flakeLockDigest" "flakeSourceDigest" "foreignLockDigest" "misaLibraryDigest" ]
          (_: mkOption { type = types.strMatching "sha256:[0-9a-f]{64}"; });
      };
    };
    annotations = mkOption { type = types.attrsOf types.str; default = { }; };

    kernel = {
      packages = mkOption {
        type = types.raw;
        default = pkgs.linuxPackages;
        description = "Kernel package set; its kernel, modules and stage-1 module closure must agree.";
      };
      modules = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Modules the kernel-modules oneshot loads in stage 2.";
      };
    };

    boot = {
      stage1 = mkOption {
        type = types.enum [ "not-os" "nixos-scripted" ];
        description = "Borrowed stage 1 under qualification (Chapter 12, borrowed stage 1).";
      };
      initrdModules = mkOption {
        type = types.listOf types.str;
        default = [ "virtio_pci" "virtio_blk" "ext4" ];
        description = "Modules needed to reach the root; dependencies are resolved at build time.";
      };
      root = {
        selector = mkOption { type = selector; };
        fstype = mkOption { type = types.enum [ "ext4" ]; default = "ext4"; };
        mountFlags = mkOption { type = types.listOf (types.enum [ "rw" "ro" "noatime" "relatime" ]); default = [ "rw" ]; };
      };
      waitSeconds = mkOption { type = types.ints.between 1 300; default = 10; };
      cmdline = mkOption { type = types.listOf types.str; default = [ "console=ttyS0,115200" ]; };
      publisher = mkOption {
        type = types.attrs;
        default = {
          type = "bls1";
          titleKey = config.misa.hostId;
          sortKey = "misa";
          rescue = false;
          # B6: the loader's features are unknown until one successful boot.
          selection = "manual";
          tries = 0;
        };
      };
      health = mkOption {
        type = types.attrs;
        default = {
          gates = [ "base-target" "init-handoff" ];
          bless.requires = [ "base-target" ];
          blessTimeoutSec = 120;
        };
      };
    };

    services = mkOption { type = types.attrsOf service; default = { }; };
    targets = mkOption { type = types.attrsOf (types.listOf id); default = { }; };

    environment = {
      packages = mkOption { type = types.listOf types.package; default = [ ]; };
      etc = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = "File contents under the generation's /etc, by relative path.";
      };
    };

    testing.backdoor = mkOption {
      type = types.bool;
      default = false;
      description = "Test-only root shell on /dev/hvc0 for the NixOS test driver. Never in a production generation.";
    };

    build = mkOption {
      type = types.attrsOf types.raw;
      internal = true;
      description = "Build products: graph, initTree, initrd, toplevel, plan, generation.";
    };
  };
}
