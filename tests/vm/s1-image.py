#!/usr/bin/env python3
"""Build the S1 fixture images: Debian-derived, unsigned OCI layouts plus locks.

The result is a real OCI image built on the pinned official Debian bookworm
manifest: its original layer blob and config are reused byte for byte, a layer
holding the pinned x11-apps closure (read straight from the .deb archives, SHA-256
pinned by tests/vm/s1-debs.lock.json) and a small fixture layer are appended.
Version 2 appends one more layer to version 1, so both images share ancestors.

Nothing here signs anything. Publisher signatures are made later, with an
independent key, by `misa strata publisher-sign`; the official Docker image carries
no publisher signature and none is invented for it.
"""
import argparse
import io
import json
import os
import posixpath
import sys
import tarfile

from ocifixture import Tree, canonical, drop_staging, publish, read_base, sha256, stage_layer, write_lock

# Official Debian images use the debuerreotype epoch of the pinned manifest.
EPOCH = 1791158400
CREATED = "2026-10-05T00:00:00Z"
USR_MERGED = {"bin", "sbin", "lib", "lib32", "lib64", "libx32"}


def relocate(path):
    """Debian packages may still ship /lib, /bin... but the image is usr-merged."""
    head = path.split("/", 1)[0]
    return "usr/" + path if head in USR_MERGED else path


def strip(path):
    while path.startswith("./"):
        path = path[2:]
    path = path.rstrip("/")
    return None if path in ("", ".") else path


def deb_members(path):
    """Yield (name, bytes) for the members of an ar archive (.deb)."""
    with open(path, "rb") as handle:
        if handle.read(8) != b"!<arch>\n":
            sys.exit(f"{path}: not an ar archive")
        while True:
            header = handle.read(60)
            if len(header) < 60:
                return
            name = header[:16].decode().strip().rstrip("/")
            size = int(header[48:58])
            body = handle.read(size)
            if size % 2:
                handle.read(1)
            yield name, body


def read_deb(tree, path):
    data_member = None
    for name, body in deb_members(path):
        if name.startswith("data.tar"):
            data_member = (name, body)
    if data_member is None:
        sys.exit(f"{path}: no data.tar member")
    name, body = data_member
    if name.endswith(".zst"):
        sys.exit(f"{path}: zstd data member is not supported by this builder")
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as archive:
        for member in archive:
            original = strip(member.name)
            if original is None:
                continue
            target = relocate(original)
            origin = os.path.basename(path)
            if member.isdir():
                tree.directory(target, origin)
            elif member.isfile():
                data = archive.extractfile(member).read()
                contents[original] = data
                mode = 0o755 if member.mode & 0o111 else 0o644
                tree.file(target, data, mode, origin)
            elif member.islnk():
                source = strip(member.linkname)
                if source not in contents:
                    sys.exit(f"{path}: hardlink {original} to unseen {source}")
                data = contents[source]
                contents[original] = data
                mode = 0o755 if member.mode & 0o111 else 0o644
                tree.file(target, data, mode, origin)
            elif member.issym():
                link = member.linkname
                if original != target and not link.startswith("/"):
                    # Re-express a relative link that moved under /usr in the merged layout.
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname("/" + original), link))
                    link = posixpath.relpath(relocate(resolved.lstrip("/")), posixpath.dirname(target))
                tree.add(target, {"kind": "symlink", "mode": 0o777, "link": link}, origin)
            else:
                sys.exit(f"{path}: unsupported member type for {original}")




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-layout", required=True)
    parser.add_argument("--debs-lock", required=True)
    parser.add_argument("--debs-dir", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--desktop-entry", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    base_descriptor, base_manifest, base_config = read_base(args.base_layout)
    if len(base_manifest["layers"]) != 1:
        sys.exit("the pinned Debian base is expected to have exactly one layer")
    os.makedirs(args.out)

    # The unmodified official image: only a lock, for the unsigned negative scenario.
    write_lock(args.out, "debian-upstream", "docker.io/library/debian", base_descriptor, "glibc")

    with open(args.debs_lock) as handle:
        debs = json.load(handle)
    layer1 = Tree()
    listing = []
    for package in debs["packages"]:
        deb = os.path.join(args.debs_dir, os.path.basename(package["filename"]))
        with open(deb, "rb") as handle:
            if sha256(handle.read()) != package["sha256"]:
                sys.exit(f"{deb}: SHA-256 differs from the pinned lock")
        read_deb(layer1, deb)
        listing.append(f"{package['package']} {package['version']}\n")
    layer1.directory("mnt/share")
    layer1.directory("usr/local/bin")
    layer1.directory("usr/share/applications")
    layer1.directory("usr/share/misa-fixture")
    layer1.file("usr/local/bin/misa-probe", open(args.probe, "rb").read(), 0o755)
    layer1.file("usr/share/applications/misa-s1-xclock.desktop", open(args.desktop_entry, "rb").read())
    layer1.file("usr/share/misa-fixture/packages.txt", "".join(listing))
    layer1.file("usr/share/misa-fixture/v1-only", "present in release 1 only\n")
    layer1.file("etc/misa-fixture-release", "1\n")

    layer2 = Tree()
    layer2.directory("usr/share/misa-fixture")
    layer2.file("usr/share/misa-fixture/v2-only", "added by release 2\n")
    # OCI whiteout: release 2 deletes a file release 1 shipped.
    layer2.file("usr/share/misa-fixture/.wh.v1-only", b"")
    layer2.file("etc/misa-fixture-release", "2\n")

    layers = [stage_layer(args.out, str(number), tree, EPOCH) for number, tree in ((1, layer1), (2, layer2))]
    base_layer = {**base_manifest["layers"][0], "from": args.base_layout}

    def config_with(extra):
        config = json.loads(json.dumps(base_config))
        config["rootfs"]["diff_ids"] += [layer["diffId"] for layer in extra]
        config["history"] = base_config["history"] + [
            {
                "created": CREATED,
                "created_by": f"misa S1 fixture publisher layer {number}",
                "comment": "Debian x11-apps closure from snapshot.debian.org plus fixture files"
                if number == 1
                else "fixture release 2 delta",
            }
            for number, _ in enumerate(extra, 1)
        ]
        config["config"]["Labels"] = {
            "io.misa.fixture": "S1 derived image; the fixture publisher is not the Debian project",
            "org.opencontainers.image.base.digest": base_descriptor["digest"],
        }
        return config

    summary = {
        "base": base_descriptor["digest"],
        "v1": publish(args.out, "debian-desktop-v1", args.source, config_with(layers[:1]), [base_layer, layers[0]], "glibc"),
        "v2": publish(args.out, "debian-desktop-v2", args.source, config_with(layers), [base_layer, layers[0], layers[1]], "glibc"),
    }
    drop_staging(args.out)
    with open(os.path.join(args.out, "summary.json"), "wb") as handle:
        handle.write(canonical(summary))


if __name__ == "__main__":
    main()
