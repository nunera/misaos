#!/usr/bin/env python3
"""Exercise synthetic S0 records, without executing roots, booting or activating."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def reversed_objects(value):
    if isinstance(value, dict):
        return {key: reversed_objects(value[key]) for key in reversed(value)}
    if isinstance(value, list):
        return [reversed_objects(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--nix-wire", type=Path)
    for domain in ("strata", "plan", "generation"):
        parser.add_argument("--" + domain, type=Path, required=True)
    args = parser.parse_args()

    def cli(*arguments, reject=False):
        result = subprocess.run(
            [args.tool, *map(str, arguments)], capture_output=True, check=False
        )
        if reject:
            require(result.returncode != 0, f"accepted invalid input: {arguments}")
            error = json.loads(result.stderr)
            require(isinstance(error, dict) and "code" in error,
                    f"rejection lacks structured error: {arguments}")
        else:
            require(result.returncode == 0,
                    f"CLI failed: {arguments}\n{result.stderr.decode(errors='replace')}")
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="misa-s0-records-") as temporary:
        temporary = Path(temporary)
        vectors = json.loads((args.fixtures / "wire.json").read_bytes())["vectors"]
        encoded = (
            {row["name"]: row["source"] for row in json.loads(args.nix_wire.read_bytes())}
            if args.nix_wire else {}
        )
        for vector in vectors:
            wire = temporary / (vector["name"] + ".json")
            wire.write_bytes(bytes.fromhex(vector["sourceHex"]))
            if "canonicalHex" in vector:
                expected = bytes.fromhex(vector["canonicalHex"])
                canonical = cli("jcs", wire)
                require(canonical == expected and sha256(canonical) == vector["digest"],
                        f"wire golden mismatch: {vector['name']}")
                if args.nix_wire:
                    wire.write_text(encoded[vector["name"]], encoding="utf-8")
                    require(cli("jcs", wire) == expected,
                            f"Nix encoding changes wire identity: {vector['name']}")
            else:
                cli("jcs", wire, reject=True)
        records = {}
        digests = {}
        for domain in ("strata", "plan", "generation"):
            produced = getattr(args, domain)
            source = args.fixtures / f"{domain}.json"
            canonical = cli("canonicalize", source, "--expect", domain)
            require(produced.read_bytes() == canonical,
                    f"Nix producer and Rust canonical consumer differ: {domain}")
            require(cli("canonicalize", produced, "--expect", domain) == canonical,
                    f"canonicalization is not idempotent: {domain}")
            record = json.loads(canonical)
            records[domain] = record
            require(record["schemaVersion"] == f"misa.{domain}/v1",
                    f"wrong authority discriminator: {domain}")
            receipt = json.loads(cli("validate", produced, "--expect", domain))
            require(receipt["schemaVersion"] == record["schemaVersion"],
                    f"receipt domain mismatch: {domain}")
            require(receipt["validationScope"] == "schema-and-semantics-only",
                    f"receipt overstates validation scope: {domain}")
            require(receipt["rawDigest"] == sha256(canonical),
                    f"raw-byte identity mismatch: {domain}")
            digest = cli("digest", produced, "--expect", domain).decode().strip()
            digests[domain] = digest
            require(receipt["digest"] == digest, f"receipt digest mismatch: {domain}")
            if domain != "generation":
                require(digest == sha256(canonical), f"semantic digest mismatch: {domain}")

            reordered = temporary / f"reordered-{domain}.json"
            reordered.write_text(json.dumps(reversed_objects(record), indent=4) + "\n",
                                 encoding="utf-8")
            require(cli("canonicalize", reordered, "--expect", domain) == canonical,
                    f"object order or whitespace changed identity: {domain}")
            require(cli("digest", reordered, "--expect", domain).decode().strip() == digest,
                    f"digest is not deterministic: {domain}")
            for other in ("strata", "plan", "generation"):
                if other != domain:
                    cli("validate", produced, "--expect", other, reject=True)

            unknown = temporary / f"unknown-{domain}.json"
            unknown.write_text(json.dumps({**record, "unknownOperation": "forbidden"}),
                               encoding="utf-8")
            cli("validate", unknown, "--expect", domain, reject=True)
            duplicate = temporary / f"duplicate-{domain}.json"
            duplicate.write_bytes(b'{"schemaVersion":' +
                                  json.dumps(record["schemaVersion"]).encode() + b"," +
                                  canonical[1:])
            cli("validate", duplicate, "--expect", domain, reject=True)

        generation = records["generation"]
        body = {key: value for key, value in generation.items() if key != "generationId"}
        require(body == json.loads((args.fixtures / "generation-body.json").read_bytes()),
                "generation body fixture differs from committed generation")
        body_file = temporary / "generation-body.json"
        body_file.write_text(json.dumps(body), encoding="utf-8")
        expected_id = sha256(cli("jcs", body_file))
        require(generation["generationId"] == expected_id,
                "generationId does not bind the canonical generation body")
        require(cli("generation-id", body_file).decode().strip() == expected_id,
                "generation-id command disagrees with independent SHA-256")
        require(digests["generation"] == expected_id,
                "generation semantic digest must exclude its generationId")
        require(generation["planDigest"] == digests["plan"],
                "generation fixture does not bind the plan fixture")
        require(generation["roots"] == sorted(root["digest"] for root in records["plan"]["roots"]),
                "generation fixture does not bind the plan's root manifests")

        tampered = copy.deepcopy(generation)
        tampered["generationId"] = "sha256:" + ("0" if expected_id[-1] != "0" else "1") * 64
        tampered_file = temporary / "tampered-generation.json"
        tampered_file.write_text(json.dumps(tampered), encoding="utf-8")
        cli("validate", tampered_file, "--expect", "generation", reject=True)

        # A discriminator change cannot launder a standalone record into host authority.
        spoofed = copy.deepcopy(records["strata"])
        spoofed["schemaVersion"] = "misa.plan/v1"
        spoofed_file = temporary / "spoofed-host.json"
        spoofed_file.write_text(json.dumps(spoofed), encoding="utf-8")
        cli("validate", spoofed_file, "--expect", "plan", reject=True)

        traversal = copy.deepcopy(records["plan"])
        traversal["host"]["topLevel"] = "/nix/store/../etc"
        traversal_file = temporary / "traversal.json"
        traversal_file.write_text(json.dumps(traversal), encoding="utf-8")
        cli("validate", traversal_file, "--expect", "plan", reject=True)

    print("S0 passed: locked Nix declarations match strict Rust records; canonical digests, "
          "generation identity and authority-domain rejection checked. "
          "Synthetic schema fixtures only: no VM, root execution, image verification or activation.")


if __name__ == "__main__":
    main()
