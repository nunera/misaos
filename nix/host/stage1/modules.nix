# Modules a stage 1 must load to reach the root, with dependencies resolved at build
# time (Chapter 12, H3): `order` lists names in load order and each `<name>.ko` is
# stored decompressed, so the initrd loads a fixed list without parsing modules.dep.
{ pkgs, lib, kernel, names }:
pkgs.runCommand "misa-initrd-modules-${kernel.modDirVersion}"
{
  nativeBuildInputs = [ pkgs.kmod pkgs.xz pkgs.zstd ];
} ''
  mkdir -p "$out"
  : > order
  for name in ${lib.escapeShellArgs names}; do
    modprobe --show-depends -S ${kernel.modDirVersion} -d ${kernel.modules} "$name" > deps
    while read -r kind path rest; do
      case "$kind" in
        insmod)
          base=$(basename "$path"); base=''${base%.xz}; base=''${base%.zst}; base=''${base%.ko}
          if ! grep -qx "$base" order; then
            case "$path" in
              *.xz) xz -dc "$path" ;;
              *.zst) zstd -dc "$path" ;;
              *) cat "$path" ;;
            esac > "$out/$base.ko"
            echo "$base" >> order
          fi
          ;;
        builtin) ;;
        *) echo "unexpected modprobe output: $kind $path $rest" >&2; exit 1 ;;
      esac
    done < deps
  done
  cp order "$out/order"
''
