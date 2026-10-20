# Candidate 2 (Chapter 12, borrowed stage 1): NixOS's scripted stage 1 from the
# pinned nixos-26.05 Nixpkgs with systemd stage 1 disabled. Upstream deprecated it in
# 26.05 and schedules its removal for 26.11, so this is a bounded-horizon fallback,
# never the sole baseline. Only `config.system.build.initialRamdisk` is used: no NixOS
# stage 2, systemd or activation script runs. The root file system is fixed at
# evaluation time from the same selector the manifest records; `init=` names the
# generation's misa-handoff, which re-checks the selector by content.
{ pkgs, lib, kernel, cfg }:
let
  modules = import ./modules.nix { inherit pkgs lib kernel; names = cfg.boot.initrdModules; };
  device =
    let s = cfg.boot.root.selector;
    in if s.kind == "partuuid" then "/dev/disk/by-partuuid/${s.value}" else "/dev/disk/by-uuid/${s.value}";
  nixos = import "${pkgs.path}/nixos/lib/eval-config.nix" {
    system = null;
    modules = [
      {
        nixpkgs.pkgs = pkgs;
        boot.kernelPackages = cfg.kernel.packages;
        boot.initrd.systemd.enable = false;
        boot.initrd.includeDefaultModules = false;
        boot.initrd.availableKernelModules = [ ];
        boot.initrd.kernelModules = cfg.boot.initrdModules;
        boot.loader.grub.enable = false;
        fileSystems."/" = {
          inherit device;
          fsType = cfg.boot.root.fstype;
          options = cfg.boot.root.mountFlags;
        };
        system.stateVersion = "26.05";
      }
    ];
  };
in
{
  inherit modules;
  initrd = nixos.config.system.build.initialRamdisk;
  description = "NixOS ${lib.version} scripted stage 1 (boot.initrd.systemd.enable = false)";
  cmdline = toplevel: [ "init=${toplevel}/init" ];
  warnings = lib.filter (w: lib.hasInfix "Scripted initrd" w) nixos.config.warnings;
}
