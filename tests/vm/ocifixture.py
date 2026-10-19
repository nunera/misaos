"""Deterministic OCI layout writing shared by the VM fixture image builders.

Fixture images reuse an official base's layer blobs and config byte for byte and
append deterministic gzip layers. Nothing here signs anything: publisher statements
are made later, with an independent key, by `misa strata publisher-sign`.
"""
import gzip
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"

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


class Tree:
    """Merged file tree of one new layer: path -> entry dict."""

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


def write_layer(tree, epoch):
    """Deterministic GNU tar (no PAX), root-owned, fixed mtime, parents sorted first."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for path in sorted(tree.entries):
            entry = tree.entries[path]
            info = tarfile.TarInfo(path)
            info.mtime = epoch
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


def read_base(layout):
    """(index descriptor, manifest, config) of a single-manifest OCI layout."""
    with open(os.path.join(layout, "index.json"), "rb") as handle:
        descriptor = json.load(handle)["manifests"][0]
    manifest = json.loads(read_blob(layout, descriptor["digest"]))
    config = json.loads(read_blob(layout, manifest["config"]["digest"]))
    return descriptor, manifest, config


def stage_layer(out, label, tree, epoch):
    """Write one new gzip layer into a private staging layout; return its descriptor."""
    raw, packed = write_layer(tree, epoch)
    staging = os.path.join(out, f".layer-{label}")
    os.makedirs(os.path.join(staging, "blobs", "sha256"))
    return {
        **write_blob(staging, packed),
        "mediaType": OCI_GZIP,
        "from": staging,
        "diffId": "sha256:" + sha256(raw),
    }


def drop_staging(out):
    for name in os.listdir(out):
        if name.startswith(".layer-"):
            shutil.rmtree(os.path.join(out, name))


def lock_for(name, source, manifest, libc):
    return {
        "schemaVersion": 1,
        "strata": {
            name: {
                "image": {
                    "digest": manifest["digest"],
                    "mediaType": OCI_MANIFEST,
                    "size": str(manifest["size"]),
                },
                "libcFamily": libc,
                "limits": LIMITS,
                "source": source,
            }
        },
        "targetPlatform": "linux/amd64",
    }


def write_lock(out, name, source, manifest, libc):
    os.makedirs(os.path.join(out, name), exist_ok=True)
    with open(os.path.join(out, name, "lock.json"), "wb") as handle:
        handle.write(canonical(lock_for(name, source, manifest, libc)))


def publish(out, name, source, config, layers, libc):
    """Write one complete OCI layout and its lock; layers carry their source layout in `from`."""
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
    write_lock(out, name, source, entry, libc)
    return entry
