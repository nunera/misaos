#!/usr/bin/env python3
"""Resolve the pinned Debian package closure the S1 fixture image adds.

Regenerates tests/vm/s1-debs.lock.json from two immutable inputs:

* the snapshot.debian.org ``Packages.xz`` named in the lock (SHA-256 pinned), and
* the ``var/lib/dpkg/status`` file of the pinned base image layer, so packages the
  base already ships are never replaced.

Not used at test time: the checked-in lock is the pin, tests/vm/s1-fixture.nix
fetches every listed .deb by SHA-256. Run this only to move the pin:

    s1-resolve-debs.py --packages Packages.xz --status base-dpkg-status \
        --snapshot 20261005T000000Z --root x11-apps --exclude man-db > s1-debs.lock.json
"""
import argparse
import hashlib
import json
import lzma
import re
import sys


def stanzas(text):
    for block in text.split("\n\n"):
        fields, key = {}, None
        for line in block.split("\n"):
            if not line:
                continue
            if line[0] in " \t":
                if key:
                    fields[key] += "\n" + line
                continue
            key, _, value = line.partition(":")
            fields[key] = value.strip()
        if "Package" in fields:
            yield fields


def alternatives(field):
    for clause in field.split(","):
        clause = clause.strip()
        if clause:
            yield [re.split(r"[ (:]", alt.strip(), maxsplit=1)[0] for alt in clause.split("|")]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packages", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args()

    raw = open(args.packages, "rb").read()
    index = {}
    provides = {}
    for pkg in stanzas(lzma.decompress(raw).decode()):
        index[pkg["Package"]] = pkg
        for clause in alternatives(pkg.get("Provides", "")):
            provides.setdefault(clause[0], []).append(pkg["Package"])
    base = {p["Package"]: p["Version"] for p in stanzas(open(args.status).read())}
    base_provides = set()
    for pkg in stanzas(open(args.status).read()):
        for clause in alternatives(pkg.get("Provides", "")):
            base_provides.add(clause[0])

    chosen, queue = {}, list(args.root)
    while queue:
        name = queue.pop()
        if name in chosen or name in base:
            continue
        pkg = index[name]
        chosen[name] = pkg
        for field in ("Depends", "Pre-Depends"):
            for clause in alternatives(pkg.get(field, "")):
                satisfied = False
                for alt in clause:
                    if alt in base or alt in base_provides:
                        satisfied = True
                        break
                if satisfied:
                    continue
                for alt in clause:
                    if alt in args.exclude:
                        continue
                    if alt in index:
                        queue.append(alt)
                        break
                    if alt in provides:
                        queue.append(sorted(provides[alt])[0])
                        break
                else:
                    if not all(alt in args.exclude for alt in clause):
                        sys.exit(f"{name}: unresolved dependency {clause}")

    packages = [
        {
            "package": name,
            "version": pkg["Version"],
            "filename": pkg["Filename"],
            "sha256": pkg["SHA256"],
            "size": int(pkg["Size"]),
        }
        for name, pkg in sorted(chosen.items())
    ]
    json.dump(
        {
            "schemaVersion": 1,
            "snapshot": args.snapshot,
            "urlPrefix": f"https://snapshot.debian.org/archive/debian/{args.snapshot}/",
            "packagesSha256": hashlib.sha256(raw).hexdigest(),
            "roots": args.root,
            "excluded": sorted(args.exclude),
            "baseProvided": sorted(base),
            "packages": packages,
        },
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    print()


if __name__ == "__main__":
    main()
