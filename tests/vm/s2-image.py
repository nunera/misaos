#!/usr/bin/env python3
"""Build the S2 fixture: a Void-musl-derived, unsigned OCI layout plus locks.

The derived image reuses the pinned official ghcr.io/void-linux/void-musl manifest's
layer blobs byte for byte and appends one fixture layer. It adds no xbps packages:
Void keeps no dated public package archive, so hash-pinned package fetches would
disappear upstream. The layer carries the shared probe, a release marker and one
foreign glibc ELF (Debian's /usr/bin/true from the pinned S1 base) for the typed
cross-libc refusal.

The builder also records each root's own package database as an independent oracle:
Debian's dpkg status from the pinned S1 base layer and Void's xbps pkgdb from the
pinned Void layers. Nothing here signs anything.
"""
import argparse
import gzip
import json
import os
import plistlib
import sys
import tarfile

from ocifixture import Tree, canonical, drop_staging, publish, read_base, stage_layer, write_lock

EPOCH = 1790812800
CREATED = "2026-10-01T12:00:00Z"
PKGDB = "var/db/xbps/pkgdb-0.38.plist"
DPKG_STATUS = "var/lib/dpkg/status"


def normal(name):
    while name.startswith("./"):
        name = name[2:]
    return name


def layer_file(layout, descriptor, wanted):
    """Bytes of `wanted` in one gzip layer, or None when the layer does not ship it."""
    path = os.path.join(layout, "blobs", "sha256", descriptor["digest"].removeprefix("sha256:"))
    with gzip.open(path, "rb") as stream, tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            if normal(member.name) == wanted:
                if not member.isfile():
                    sys.exit(f"{wanted}: not a regular file in its layer")
                return archive.extractfile(member).read()
    return None


def final_file(layout, manifest, wanted):
    """The upper-most layer's copy of `wanted`; these fixtures carry no whiteouts for it."""
    data = None
    for descriptor in manifest["layers"]:
        found = layer_file(layout, descriptor, wanted)
        if found is not None:
            data = found
    if data is None:
        sys.exit(f"{wanted}: absent from every layer")
    return data


def dpkg_packages(status):
    packages = []
    for stanza in status.decode().strip().split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line[:1] not in (" ", "\t") and ":" in line:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
        if fields.get("Status") != "install ok installed":
            sys.exit(f"dpkg status entry {fields.get('Package')} is not cleanly installed")
        packages.append(f"{fields['Package']} {fields['Version']}")
    return sorted(packages)


def xbps_packages(pkgdb):
    database = plistlib.loads(pkgdb)
    packages = []
    for name, record in database.items():
        if name.startswith("_XBPS_"):
            continue
        if record.get("state") != "installed":
            sys.exit(f"xbps pkgdb entry {name} is not installed")
        packages.append(record["pkgver"])
    return sorted(packages)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-layout", required=True)
    parser.add_argument("--debian-base-layout", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    base_descriptor, base_manifest, base_config = read_base(args.base_layout)
    _, debian_manifest, _ = read_base(args.debian_base_layout)
    os.makedirs(args.out)

    # The unmodified official image: only a lock, for the unsigned negative scenario.
    write_lock(args.out, "void-musl-upstream", "ghcr.io/void-linux/void-musl", base_descriptor, "musl")

    glibc_elf = final_file(args.debian_base_layout, debian_manifest, "usr/bin/true")
    if not glibc_elf.startswith(b"\x7fELF") or b"/lib64/ld-linux-x86-64.so.2\0" not in glibc_elf:
        sys.exit("Debian /usr/bin/true is not a dynamically linked glibc ELF")

    layer = Tree()
    layer.directory("mnt/share")
    layer.directory("usr/local/bin")
    layer.directory("usr/share/misa-fixture")
    layer.file("usr/local/bin/misa-probe", open(args.probe, "rb").read(), 0o755)
    layer.file("usr/local/bin/glibc-true", glibc_elf, 0o755)
    layer.file("usr/share/misa-fixture/void-only", "present in the Void fixture only\n")
    layer.file("etc/misa-fixture-release", "1\n")
    staged = stage_layer(args.out, "void", layer, EPOCH)

    config = json.loads(json.dumps(base_config))
    config["rootfs"]["diff_ids"].append(staged["diffId"])
    config["history"] = base_config.get("history", []) + [
        {
            "created": CREATED,
            "created_by": "misa S2 fixture publisher layer",
            "comment": "probe, release marker and one foreign glibc ELF; no xbps packages",
        }
    ]
    # Replace the Void team's labels: the fixture publisher is not the Void project.
    config["config"]["Labels"] = {
        "io.misa.fixture": "S2 derived image; the fixture publisher is not the Void Linux project",
        "org.opencontainers.image.base.digest": base_descriptor["digest"],
    }
    layers = [{**descriptor, "from": args.base_layout} for descriptor in base_manifest["layers"]]
    derived = publish(args.out, "void-musl-v1", args.source, config, layers + [staged], "musl")
    drop_staging(args.out)

    expected = {
        "dpkg": dpkg_packages(final_file(args.debian_base_layout, debian_manifest, DPKG_STATUS)),
        "xbps": xbps_packages(final_file(args.base_layout, base_manifest, PKGDB)),
    }
    if not expected["dpkg"] or not expected["xbps"]:
        sys.exit("a fixture root has an empty package database")
    with open(os.path.join(args.out, "summary.json"), "wb") as handle:
        handle.write(canonical({"base": base_descriptor["digest"], "v1": derived, "packages": expected}))


if __name__ == "__main__":
    main()
