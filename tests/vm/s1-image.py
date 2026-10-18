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
import gzip
import hashlib
import io
import json
import os
import posixpath
import shutil
import sys
import tarfile

# Official Debian images use the debuerreotype epoch of the pinned manifest.
EPOCH = 1791158400
CREATED = "2026-10-05T00:00:00Z"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
USR_MERGED = {"bin", "sbin", "lib", "lib32", "lib64", "libx32"}

LIMITS = {
    "maxBlobBytes": "536870912",
    "maxEntries": 200000,
    "maxExpandedBytes": "2147483648",
    "maxExpansionRatio": 256,
    "maxFileBytes": "536870912",
    "maxPathBytes": 4096,
    "timeoutSeconds": 300,
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


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


class Tree:
    """Merged file tree of the new layer: path -> entry dict."""

    def __init__(self):
        self.entries = {}

    def add(self, path, entry, origin):
        existing = self.entries.get(path)
        if existing is not None:
            if existing["kind"] == "dir" and entry["kind"] == "dir":
                return
            if existing == entry:
                return
            sys.exit(f"conflicting entries for {path}: {origin} vs previous")
        self.entries[path] = entry

    def directory(self, path, origin="fixture"):
        self.add(path, {"kind": "dir", "mode": 0o755}, origin)

    def file(self, path, data, mode=0o644, origin="fixture"):
        if isinstance(data, str):
            data = data.encode()
        self.add(path, {"kind": "file", "mode": mode, "data": data}, origin)


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


def write_layer(tree):
    """Deterministic GNU tar (no PAX), root-owned, fixed mtime, parents sorted first."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for path in sorted(tree.entries):
            entry = tree.entries[path]
            info = tarfile.TarInfo(path)
            info.mtime = EPOCH
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = entry["mode"]
            if entry["kind"] == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif entry["kind"] == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry["link"]
                archive.addfile(info)
            else:
                info.size = len(entry["data"])
                archive.addfile(info, io.BytesIO(entry["data"]))
    raw = buffer.getvalue()
    packed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=packed, mtime=0, compresslevel=9) as stream:
        stream.write(raw)
    return raw, packed.getvalue()


def read_blob(layout, digest):
    with open(os.path.join(layout, "blobs", "sha256", digest.removeprefix("sha256:")), "rb") as handle:
        return handle.read()


def write_blob(layout, data):
    digest = sha256(data)
    with open(os.path.join(layout, "blobs", "sha256", digest), "wb") as handle:
        handle.write(data)
    return {"digest": "sha256:" + digest, "size": len(data)}


def lock_for(name, source, manifest):
    return {
        "schemaVersion": 1,
        "strata": {
            name: {
                "image": {
                    "digest": manifest["digest"],
                    "mediaType": OCI_MANIFEST,
                    "size": str(manifest["size"]),
                },
                "libcFamily": "glibc",
                "limits": LIMITS,
                "source": source,
            }
        },
        "targetPlatform": "linux/amd64",
    }


def publish(out, name, source, base_layout, config, layers):
    """Write one complete OCI layout whose manifest has the given layer blobs."""
    layout = os.path.join(out, name, "layout")
    os.makedirs(os.path.join(layout, "blobs", "sha256"))
    for layer in layers:
        shutil.copyfile(
            os.path.join(layer["from"], "blobs", "sha256", layer["digest"].removeprefix("sha256:")),
            os.path.join(layout, "blobs", "sha256", layer["digest"].removeprefix("sha256:")),
        )
    config_descriptor = write_blob(layout, canonical(config))
    manifest = {
        "config": {"mediaType": OCI_CONFIG, **config_descriptor},
        "layers": [
            {"mediaType": layer["mediaType"], "digest": layer["digest"], "size": layer["size"]}
            for layer in layers
        ],
        "mediaType": OCI_MANIFEST,
        "schemaVersion": 2,
    }
    descriptor = write_blob(layout, canonical(manifest))
    entry = {"mediaType": OCI_MANIFEST, **descriptor, "platform": {"architecture": "amd64", "os": "linux"}}
    with open(os.path.join(layout, "oci-layout"), "wb") as handle:
        handle.write(b'{"imageLayoutVersion":"1.0.0"}')
    with open(os.path.join(layout, "index.json"), "wb") as handle:
        handle.write(canonical({"manifests": [entry], "mediaType": OCI_INDEX, "schemaVersion": 2}))
    with open(os.path.join(out, name, "lock.json"), "wb") as handle:
        handle.write(canonical(lock_for(name, source, entry)))
    return entry


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

    with open(os.path.join(args.base_layout, "index.json"), "rb") as handle:
        base_index = json.load(handle)
    base_descriptor = base_index["manifests"][0]
    base_manifest = json.loads(read_blob(args.base_layout, base_descriptor["digest"]))
    base_config = json.loads(read_blob(args.base_layout, base_manifest["config"]["digest"]))
    if len(base_manifest["layers"]) != 1:
        sys.exit("the pinned Debian base is expected to have exactly one layer")
    os.makedirs(args.out)

    # The unmodified official image: only a lock, for the unsigned negative scenario.
    os.makedirs(os.path.join(args.out, "debian-upstream"))
    with open(os.path.join(args.out, "debian-upstream", "lock.json"), "wb") as handle:
        handle.write(
            canonical(lock_for("debian-upstream", "docker.io/library/debian", base_descriptor))
        )

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

    layers = []
    for number, tree in ((1, layer1), (2, layer2)):
        raw, packed = write_layer(tree)
        staging = os.path.join(args.out, f".layer{number}")
        os.makedirs(os.path.join(staging, "blobs", "sha256"))
        descriptor = write_blob(staging, packed)
        layers.append(
            {
                **descriptor,
                "mediaType": OCI_GZIP,
                "from": staging,
                "diffId": "sha256:" + sha256(raw),
            }
        )
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
        "v1": publish(args.out, "debian-desktop-v1", args.source, args.base_layout, config_with(layers[:1]), [base_layer, layers[0]]),
        "v2": publish(args.out, "debian-desktop-v2", args.source, args.base_layout, config_with(layers), [base_layer, layers[0], layers[1]]),
    }
    for number in (1, 2):
        shutil.rmtree(os.path.join(args.out, f".layer{number}"))
    with open(os.path.join(args.out, "summary.json"), "wb") as handle:
        handle.write(canonical(summary))


if __name__ == "__main__":
    main()
