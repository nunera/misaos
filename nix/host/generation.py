#!/usr/bin/env python3
"""Assemble a misa.generation/v1 manifest from built artifacts.

Every digest and size is read from the actual store files; `misa-plan` computes the
generation ID and validates the result. `--patch POINTER=JSON` replaces one value of
the body before the ID is computed, which is how test fixtures build internally
consistent manifests that must still be refused at boot.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def store_file(path):
    """The store path itself (never its resolved target), its digest and size."""
    return {"store": path, "sha256": sha256(path), "size": str(os.path.getsize(path))}


def set_pointer(doc, pointer, value):
    parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer.lstrip("/").split("/")]
    for part in parts[:-1]:
        doc = doc[int(part)] if isinstance(doc, list) else doc[part]
    last = parts[-1]
    if isinstance(doc, list):
        doc[int(last)] = value
    else:
        if last not in doc:
            sys.exit(f"--patch {pointer}: no such field")
        doc[last] = value


def main():
    p = argparse.ArgumentParser()
    for name in ("plan", "plan-digest", "kernel-image", "kernel-uname", "modules-dir",
                 "initrd", "initrd-build-id", "module-order", "init", "tree",
                 "firmware-dir", "misa-plan", "out"):
        p.add_argument(f"--{name}", required=True)
    p.add_argument("--cmdline-limit", type=int, default=2048)
    p.add_argument("--patch", action="append", default=[])
    a = p.parse_args()

    plan = json.load(open(a.plan))
    plan_digest = open(a.plan_digest).read().strip()
    tree = sha256(a.tree)
    order = [line.strip() for line in open(a.module_order) if line.strip()]
    kernel = store_file(a.kernel_image)
    kernel.update({"uname": a.kernel_uname, "cmdlineLimit": a.cmdline_limit})
    body = {
        "schemaVersion": "misa.generation/v1",
        "machineId": plan["machineId"],
        "planDigest": plan_digest,
        "roots": sorted(r["digest"] for r in plan["roots"]),
        "requiredFeatures": [],
        "adapterIdentity": tree,
        "boot": {
            "schema": "misa.boot/v1",
            "platform": {"arch": plan["target"]["kernelArch"]},
            "kernel": kernel,
            "initrd": {
                "buildId": a.initrd_build_id,
                "parts": [dict(role="main", **store_file(a.initrd))],
            },
            "cmdline": plan["boot"]["cmdline"],
            "root": plan["boot"]["root"],
            "unlock": plan["boot"]["unlock"],
            "mounts": [],
            "init": {
                "path": a.init,
                "sha256": sha256(a.init),
                "elfMachine": {"x86_64": 62, "aarch64": 183}[plan["target"]["kernelArch"]],
                "adapterId": plan["host"]["initAdapter"],
                "adapterBuildId": tree,
            },
            "modules": {"dir": a.modules_dir, "uname": a.kernel_uname, "initrdOrder": order},
            "firmware": {"dir": a.firmware_dir, "initrdFiles": []},
            "publisher": plan["boot"]["publisher"],
            "health": plan["boot"]["health"],
        },
    }
    for patch in a.patch:
        pointer, _, value = patch.partition("=")
        set_pointer(body, pointer, json.loads(value))

    os.makedirs(a.out)
    body_path = os.path.join(a.out, "body.json")
    with open(body_path, "w") as f:
        json.dump(body, f)
    run = lambda *args: subprocess.run([a.misa_plan, *args], check=True, capture_output=True, text=True).stdout
    body["generationId"] = run("generation-id", body_path).strip()
    os.remove(body_path)
    raw = os.path.join(a.out, "raw.json")
    with open(raw, "w") as f:
        json.dump(body, f)
    canonical = subprocess.run([a.misa_plan, "canonicalize", raw, "--expect", "generation"],
                               check=True, capture_output=True).stdout
    os.remove(raw)
    with open(os.path.join(a.out, "generation.json"), "wb") as f:
        f.write(canonical)
    with open(os.path.join(a.out, "id"), "w") as f:
        f.write(body["generationId"].removeprefix("sha256:"))


if __name__ == "__main__":
    main()
