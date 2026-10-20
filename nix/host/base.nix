# Baseline services of a headless Misa host on Dinit. Every service runs through
# misa-svcrun; `boot` is the milestone Dinit starts as PID 1.
{ lib, config, pkgs, misaHost, ... }:
let
  cfg = config.misa;
  sh = name: text: "${pkgs.writeShellScript name ''
    set -eu
    PATH=${lib.makeBinPath [ pkgs.coreutils pkgs.util-linux pkgs.kmod ]}
    ${text}
  ''}";
  oneshot = command: requires: {
    kind = "oneshot";
    inherit command requires;
    argv = [ (baseNameOf command) ];
  };
  mdevConf = pkgs.writeText "mdev.conf" ''
    -$MODALIAS=.* 0:0 0660 @modprobe -b "$MODALIAS"
    .* 0:0 0660
  '';
in
{
  misa.kernel.modules = [ "efivarfs" ];

  misa.environment.packages = with pkgs; [
    bashInteractive
    coreutils
    dinit
    e2fsprogs
    findutils
    gnugrep
    gnused
    kmod
    mdevd
    misaHost
    procps
    util-linux
  ];

  misa.environment.etc = {
    hostname = "${cfg.hostId}\n";
    passwd = "root:x:0:0:System administrator:/root:/run/current-system/sw/bin/bash\n";
    group = "root:x:0:\n";
    "mdev.conf" = builtins.readFile mdevConf;
    "os-release" = ''
      NAME=MisaOS
      ID=misaos
      PRETTY_NAME="MisaOS (S3a owned host)"
      VARIANT_ID=headless
    '';
  };

  misa.services = {
    kernel-modules = oneshot (sh "misa-kernel-modules" ''
      modprobe -a ${lib.escapeShellArgs cfg.kernel.modules}
    '') [ ];

    early-mounts = oneshot (sh "misa-early-mounts" ''
      mnt() { mountpoint -q "$2" || { mkdir -p "$2"; mount -t "$1" -o "$3" "$1" "$2"; }; }
      mnt devpts /dev/pts gid=5,mode=0620,ptmxmode=0666,nosuid,noexec
      mnt tmpfs /dev/shm mode=1777,nosuid,nodev
      mnt tmpfs /tmp mode=1777,nosuid,nodev
      if [ -d /sys/firmware/efi ]; then
        mnt efivarfs /sys/firmware/efi/efivars nosuid,nodev,noexec,ro
      fi
    '') [ "kernel-modules" ];

    hostname = oneshot (sh "misa-hostname" ''
      tr -d '\n' < /etc/hostname > /proc/sys/kernel/hostname
    '') [ ];

    # Device events: mdevd signals readiness on descriptor 3 once it listens.
    mdevd = {
      kind = "longrun";
      command = "${pkgs.mdevd}/bin/mdevd";
      argv = [ "mdevd" "-D" "3" "-f" "/etc/mdev.conf" "-F" "/run/current-system/firmware" ];
      env.PATH = "/run/current-system/sw/bin";
      readiness = { kind = "fd-newline"; fd = 3; timeout = 10; };
      restart = { kind = "on-failure"; burst = 3; window = 30; delay = 1; };
      requires = [ "early-mounts" ];
    };
    mdevd-coldplug = oneshot "${pkgs.mdevd}/bin/mdevd-coldplug" [ "mdevd" ];

    base = {
      kind = "milestone";
      requires = [ "early-mounts" "hostname" "kernel-modules" "mdevd-coldplug" ];
    };
    boot = {
      kind = "milestone";
      requires = [ "base" ];
    };
  };
}
