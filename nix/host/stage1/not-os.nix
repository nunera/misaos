# Candidate 1 (Chapter 12, borrowed stage 1): a reviewed adaptation of not-os's
# BusyBox stage 1, https://github.com/cleverca22/not-os, stage-1.nix at commit
# fa6ba60ab02ac3a82c27784a3b7e8eda13f7fae8 (MIT, Copyright 2016-2020 Michael Bishop).
#
# Kept from not-os: the patchelf'd BusyBox `extraUtils`, the devtmpfs/proc/sysfs
# setup, the `systemConfig=` command-line key and the final
# `exec env -i switch_root /mnt $sysconfig/init`.
# Changed for Misa:
#   * `root=/dev/vda` device names -> `misa.root=` content selector (GPT PARTUUID or
#     file-system UUID via blkid), bounded by `misa.wait=`, ambiguity is an error;
#   * squashfs/overlay/tmpfs/netroot/SD layouts -> one ext4 root mounted read-write;
#   * modprobe of a module list -> insmod of a build-time resolved, ordered list;
#   * /run is a tmpfs, and /dev /proc /sys /run move into the new root so
#     /run/misa survives the switch;
#   * no plymouth, dhcpcd or tftp; failures print and drop to the BusyBox shell.
# `$sysconfig/init` is the generation's misa-handoff, which verifies the selected
# generation before any init runs.
{ pkgs, lib, kernel, cfg }:
let
  rev = "fa6ba60ab02ac3a82c27784a3b7e8eda13f7fae8";
  modules = import ./modules.nix { inherit pkgs lib kernel; names = cfg.boot.initrdModules; };
  extraUtils = pkgs.runCommandCC "misa-not-os-extra-utils"
    {
      nativeBuildInputs = [ pkgs.nukeReferences ];
      allowedReferences = [ "out" ];
    } ''
    set +o pipefail
    mkdir -p $out/bin $out/lib
    ln -s $out/bin $out/sbin

    copy_bin_and_libs() {
      [ -f "$out/bin/$(basename $1)" ] && rm "$out/bin/$(basename $1)"
      cp -pd $1 $out/bin
    }

    for BIN in ${pkgs.busybox}/{s,}bin/*; do
      copy_bin_and_libs $BIN
    done
    copy_bin_and_libs ${lib.getBin pkgs.util-linuxMinimal}/bin/blkid

    cp -pv ${pkgs.glibc.out}/lib/ld*.so.? $out/lib

    find $out/bin $out/lib -type f | while read BIN; do
      LDD="$(ldd $BIN)" || continue
      LIBS="$(echo "$LDD" | awk '{print $3}' | sed '/^$/d')"
      for LIB in $LIBS; do
        TGT="$out/lib/$(basename $LIB)"
        if [ ! -f "$TGT" ]; then
          SRC="$(readlink -e $LIB)"
          cp -pdv "$SRC" "$TGT"
        fi
      done
    done

    chmod -R u+w $out
    stripDirs "lib bin" "-s"

    find $out/bin $out/lib -type f | while read i; do
      if ! test -L $i; then
        nuke-refs -e $out $i
      fi
    done

    find $out/bin -type f | while read i; do
      if ! test -L $i; then
        patchelf --set-interpreter $out/lib/ld*.so.? --set-rpath $out/lib $i || true
      fi
    done

    $out/bin/ash -c 'echo hello world' | grep "hello world"
    export LD_LIBRARY_PATH=$out/lib
    $out/bin/mount --help 2>&1 | grep -q "BusyBox"
    $out/bin/blkid --version | grep -q util-linux
  '';
  shell = "${extraUtils}/bin/ash";
  mountOptions = lib.concatStringsSep "," cfg.boot.root.mountFlags;
  bootStage1 = pkgs.writeScript "misa-not-os-stage1" ''
    #!${shell}
    echo
    echo "<<< MisaOS stage 1: not-os ${builtins.substring 0 7 rev} adaptation >>>"
    echo

    export PATH=${extraUtils}/bin
    fail() {
      echo "misa stage-1: $*"
      echo "misa stage-1: dropping to the BusyBox shell"
      exec ${shell}
    }
    mkdir -p /proc /sys /dev /run /tmp /mnt /bin
    mount -t devtmpfs devtmpfs /dev
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
    ln -s ${shell} /bin/sh

    for m in $(cat /lib/misa-modules/order); do
      insmod /lib/misa-modules/$m.ko || fail "insmod $m"
    done

    sysconfig=
    root=
    wait=10
    for o in $(cat /proc/cmdline); do
      case $o in
        systemConfig=*) sysconfig=''${o#systemConfig=} ;;
        misa.root=*) root=''${o#misa.root=} ;;
        misa.wait=*) wait=''${o#misa.wait=} ;;
      esac
    done
    [ -n "$sysconfig" ] || fail "no systemConfig= on the kernel command line"
    case $root in
      partuuid=*) tag=PARTUUID=''${root#partuuid=} ;;
      fsuuid=*) tag=UUID=''${root#fsuuid=} ;;
      *) fail "misa.root= must name partuuid= or fsuuid=" ;;
    esac

    tries=0
    while :; do
      devs=$(blkid -t "$tag" -o device 2>/dev/null)
      n=$(echo "$devs" | grep -c .)
      [ "$n" -eq 1 ] && break
      [ "$n" -gt 1 ] && fail "root selector $root is ambiguous: $devs"
      tries=$((tries + 1))
      [ "$tries" -gt "$wait" ] && fail "root selector $root matched no device within $wait s"
      sleep 1
    done
    echo "misa stage-1: root $root is $devs"
    mount -t ${cfg.boot.root.fstype} -o ${mountOptions} "$devs" /mnt || fail "cannot mount $devs"
    for d in dev proc sys run; do
      mkdir -p /mnt/$d
      mount --move /$d /mnt/$d || fail "cannot move /$d"
    done

    exec env -i $(type -P switch_root) /mnt "$sysconfig/init"
    fail "switch_root failed"
  '';
  initrd = pkgs.makeInitrd {
    name = "misa-not-os-initrd";
    contents = [
      { object = bootStage1; symlink = "/init"; }
      { object = modules; symlink = "/lib/misa-modules"; }
    ];
  };
in
{
  inherit initrd modules;
  description = "not-os ${rev} BusyBox stage 1, Misa adaptation";
  cmdline = toplevel: [ "systemConfig=${toplevel}" "misa.wait=${toString cfg.boot.waitSeconds}" ];
  warnings = [ ];
}
