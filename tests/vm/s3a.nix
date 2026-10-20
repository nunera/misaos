# S3a: the first Misa-owned boot. One shared ext4 root disk holds every generation's
# closure and manifest; each scenario boots its own small ESP disk carrying
# systemd-boot (loader only) and the one BLS entry misa-activate published for it.
#
#   notos / scripted   OVMF -> systemd-boot -> borrowed stage 1 -> misa-handoff -> Dinit
#   neg-*              misa-handoff refuses before any init runs
#
# The guests are not NixOS: the stock nixos-test-driver runs them from our own
# start scripts and talks to the test-generation backdoor service on /dev/hvc0.
{ pkgs, planLib, misa, misaHost }:
let
  inherit (pkgs) lib;
  qemu = pkgs.qemu_test;
  ovmf = pkgs.OVMF.fd;
  sdboot = "${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi";

  evalHost = import ../../nix/host { inherit pkgs planLib misaHost; misaTool = misa; };
  host = args: evalHost [ (import ./s3a-host.nix args) ];
  notos = host { stage1 = "not-os"; };
  scripted = host { stage1 = "nixos-scripted"; };
  production = host { stage1 = "not-os"; testing = false; };

  rootPartUuid = "5a3a0001-0000-4000-8000-00000000c0de";
  rootFsUuid = "5a3a0002-0000-4000-8000-00000000c0de";

  # A well-formed init of the wrong ISA (ELF machine 183, aarch64) for V10.
  foreignInit = pkgs.runCommand "misa-s3a-aarch64-init" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    mkdir -p $out/bin
    python3 - <<'EOF'
    import os, struct
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, 0x400000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    path = os.environ["out"] + "/bin/init"
    open(path, "wb").write(hdr)
    os.chmod(path, 0o555)
    EOF
  '';

  generations = {
    notos = { host = notos; generation = notos.generation; };
    scripted = { host = scripted; generation = scripted.generation; };
    # Consistent manifests whose init is not what they pin, or not for this machine.
    init-hash = {
      host = notos;
      generation = notos.mkGeneration {
        name = "misa-s3a-wrong-init-hash";
        patches = [ ''/boot/init/sha256="sha256:${builtins.hashString "sha256" "not the dinit binary"}"'' ];
      };
    };
    init-elf = {
      host = notos;
      generation = notos.mkGeneration { name = "misa-s3a-foreign-init"; init = "${foreignInit}/bin/init"; };
    };
    # Published intact; its stored manifest is edited afterwards (see `tamper`).
    tampered = {
      host = notos;
      generation = notos.mkGeneration {
        name = "misa-s3a-tampered";
        patches = [ ''/boot/publisher/titleKey="s3a-tamper-target"'' ];
      };
      tamper = true;
    };
    tampered-scripted = {
      host = scripted;
      generation = scripted.mkGeneration {
        name = "misa-s3a-tampered-scripted";
        patches = [ ''/boot/publisher/titleKey="s3a-tamper-target"'' ];
      };
      tamper = true;
    };
  };

  rootFs = pkgs.callPackage "${pkgs.path}/nixos/lib/make-ext4-fs.nix" {
    storePaths = [ notos.toplevel scripted.toplevel foreignInit ];
    volumeLabel = "misa-root";
    uuid = rootFsUuid;
    populateImageCommands = ''
      mkdir -p ./files/var/lib/misa/generations ./files/var/log ./files/usr \
        ./files/proc ./files/sys ./files/dev ./files/run ./files/tmp ./files/root ./files/mnt
      # Generation-independent skeleton: everything resolves through /run/current-system,
      # which misa-handoff points at the verified generation on every boot.
      ln -s /run/current-system/etc ./files/etc
      ln -s /run/current-system/sw/bin ./files/bin
      ln -s /run/current-system/sw/bin ./files/usr/bin
    '' + lib.concatStrings (lib.mapAttrsToList (name: g: ''
      d=./files/var/lib/misa/generations/$(cat ${g.generation}/id)
      mkdir -p "$d"
      cp ${g.generation}/generation.json "$d/manifest.json"
      cp ${g.host.plan}/plan.json "$d/plan.json"
      ${lib.optionalString (g.tamper or false) ''
        # Same bytes except one field: the stored manifest no longer hashes to its name.
        sed -i 's/"s3a-tamper-target"/"s3a-tampered-after-publication"/' "$d/manifest.json"
        if cmp -s ${g.generation}/generation.json "$d/manifest.json"; then exit 1; fi
      ''}
    '') generations);
  };

  gptDisk = { name, image, partUuid, type, label }: pkgs.runCommand "misa-s3a-${name}-disk"
    { nativeBuildInputs = [ pkgs.util-linux qemu ]; } ''
    bytes=$(stat -c %s ${image})
    truncate -s $(( bytes + 2 * 1024 * 1024 )) disk.raw
    sfdisk --quiet disk.raw <<EOF
    label: gpt
    first-lba: 2048
    start=2048, size=$(( bytes / 512 )), type=${type}, uuid=${partUuid}, name=${label}
    EOF
    dd if=${image} of=disk.raw bs=1M seek=1 conv=notrunc status=none
    mkdir -p $out
    qemu-img convert -f raw -O qcow2 disk.raw $out/disk.qcow2
  '';

  rootImage = pkgs.runCommand "misa-s3a-root-fs-grown" { nativeBuildInputs = [ pkgs.e2fsprogs ]; } ''
    cp ${rootFs} $out
    chmod u+w $out
    export EXT2FS_NO_MTAB_OK=yes
    e2fsck -fp $out
    resize2fs $out $(( $(stat -c %s $out) / 1024 + 262144 ))K
  '';
  rootDisk = gptDisk {
    name = "root";
    image = rootImage;
    partUuid = rootPartUuid;
    type = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    label = "misa-root";
  };

  # One boot partition per scenario: installer files, then misa-activate's publication.
  esp = name: { generation, edit ? "" }:
    let
      fat = pkgs.runCommand "misa-s3a-esp-${name}"
        { nativeBuildInputs = [ misaHost pkgs.dosfstools pkgs.mtools ]; } ''
        mkdir -p boot/EFI/BOOT boot/EFI/systemd boot/loader/entries $out
        cp ${sdboot} boot/EFI/BOOT/BOOTX64.EFI
        cp ${sdboot} boot/EFI/systemd/systemd-bootx64.efi
        printf 'timeout 0\neditor no\nconsole-mode keep\n' > boot/loader/loader.conf
        printf 'type1\n' > boot/loader/entries.srel
        misa-activate publish --boot boot --generation ${generation}/generation.json --sequence 1 \
          > $out/publication.json
        ${edit}
        cp boot/loader/entries/*.conf $out/
        kib=$(( $(du -sk boot | cut -f1) + 40960 ))
        mkfs.vfat -C -n MISA-ESP -i 5a3ae5f0 $out/esp.fat $kib > /dev/null
        export MTOOLS_SKIP_CHECK=1
        mcopy -s -i $out/esp.fat boot/* ::
      '';
    in {
      inherit fat;
      disk = gptDisk {
        name = "esp-${name}";
        image = "${fat}/esp.fat";
        partUuid = "5a3ae5f0-0000-4000-8000-00000000c0de";
        type = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
        label = "esp";
      };
    };

  scenarios = {
    notos = esp "notos" { inherit (generations.notos) generation; };
    scripted = esp "scripted" { inherit (generations.scripted) generation; };
    neg_tampered = esp "tampered" { inherit (generations.tampered) generation; };
    neg_tampered_scripted = esp "tampered-scripted" { inherit (generations.tampered-scripted) generation; };
    neg_init_hash = esp "init-hash" { inherit (generations.init-hash) generation; };
    neg_init_elf = esp "init-elf" { inherit (generations.init-elf) generation; };
    # A hand-edited entry: same file system, but named by its fs UUID instead of the
    # manifest's GPT partition UUID. Stage 1 finds and mounts it; misa-handoff refuses.
    neg_selector = esp "selector" {
      inherit (generations.notos) generation;
      edit = ''
        sed -i 's/misa.root=partuuid=${rootPartUuid}/misa.root=fsuuid=${rootFsUuid}/' boot/loader/entries/*.conf
        grep -q 'misa.root=fsuuid=${rootFsUuid}' boot/loader/entries/*.conf
      '';
    };
  };

  vm = name: scenario: pkgs.writeShellScriptBin "run-${name}-vm" ''
    set -eu
    cd "$TMPDIR"
    [ -e vars.fd ] || install -m 0600 ${ovmf}/FV/OVMF_VARS.fd vars.fd
    [ -e root.qcow2 ] || ${qemu}/bin/qemu-img create -q -f qcow2 -F qcow2 -b ${rootDisk}/disk.qcow2 root.qcow2
    [ -e esp.qcow2 ] || ${qemu}/bin/qemu-img create -q -f qcow2 -F qcow2 -b ${scenario.disk}/disk.qcow2 esp.qcow2
    exec ${qemu}/bin/qemu-kvm -machine q35 -cpu max -m 1024 -smp 2 \
      -drive if=pflash,format=raw,unit=0,readonly=on,file=${ovmf}/FV/OVMF_CODE.fd \
      -drive if=pflash,format=raw,unit=1,file=vars.fd \
      -drive if=none,id=esp,format=qcow2,file=esp.qcow2 -device virtio-blk-pci,drive=esp,bootindex=1 \
      -drive if=none,id=root,format=qcow2,file=root.qcow2 -device virtio-blk-pci,drive=root \
      -nic none "$@"
  '';

  record = name: g: {
    id = builtins.readFile "${g.generation}/id";
    manifest = "${g.generation}/generation.json";
    plan = "${g.host.plan}/plan.json";
    toplevel = "${g.host.toplevel}";
  };
  data = {
    rootPartUuid = rootPartUuid;
    generations = lib.mapAttrs record generations;
    entries = lib.mapAttrs (_: s: "${s.fat}") scenarios;
    production = {
      plan = "${production.plan}/plan.json";
      initTree = "${production.initTree}";
    };
    dinitVersion = pkgs.dinit.version;
    systemdVersion = pkgs.systemd.version;
  };

  testScript = pkgs.writeText "misa-s3a-test-script" (''
    import json
    S3A = json.loads(${builtins.toJSON (builtins.toJSON data)})
  '' + builtins.readFile ./s3a-accept.py);

  driverConfig = pkgs.writeText "misa-s3a-driver.json" (builtins.toJSON {
    vms = lib.mapAttrs (name: scenario: {
      inherit name;
      start_script = "${vm name scenario}/bin/run-${name}-vm";
    }) scenarios;
    containers = { };
    vlans = [ ];
    global_timeout = 3600;
    enable_ssh_backdoor = false;
    test_script = testScript;
  });
in
pkgs.runCommand "misa-s3a-owned-boot"
{
  requiredSystemFeatures = [ "nixos-test" "kvm" ];
  passthru = { inherit notos scripted production rootDisk scenarios; };
} ''
  mkdir -p $out
  export LOGFILE=/dev/null
  ${pkgs.nixos-test-driver}/bin/nixos-test-driver --config ${driverConfig} -o $out
''
