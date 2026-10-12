#!/usr/bin/env python3
"""Publish self-contained S0 schemas and deterministic schema-only fixtures.

Run from any directory with Python 3. No third-party dependencies or network.
The architecture's named-but-unspecified layouts are fixed by schema $comment;
these choices are not claims of an implemented boot or application runtime.
Fixture hashes identify synthetic label bytes, not artifacts or verified images.
"""
from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAFE = 9007199254740991
D = {}


def ref(name):
    return {"$ref": "#/$defs/" + name}


def string(maximum=4096, minimum=0, pattern=None):
    out = {"type": "string", "minLength": minimum, "maxLength": maximum}
    if pattern is not None:
        out["pattern"] = pattern + "(?![\\s\\S])" if pattern.endswith("$") else pattern
    return out


def integer(minimum=0, maximum=SAFE):
    return {"type": "integer", "minimum": minimum, "maximum": maximum}


def enum(*values):
    return {"enum": list(values)}


def obj(properties, optional=(), comment=None):
    out = {"type": "object", "properties": properties,
           "required": [key for key in properties if key not in optional],
           "additionalProperties": False}
    if comment:
        out["$comment"] = comment
    return out


def array(items, maximum=4096, minimum=0, ordered=False):
    out = {"type": "array", "items": items, "minItems": minimum, "maxItems": maximum}
    if not ordered:
        out["uniqueItems"] = True
        out["$comment"] = "Set-like array: semantic validation additionally requires ascending ASCII key order and unique identity keys."
    return out


def mapping(keys, values, maximum=256):
    return {"type": "object", "propertyNames": keys,
            "additionalProperties": values, "maxProperties": maximum}


def union(*branches):
    return {"oneOf": list(branches)}


def decimal_u64():
    # Enumerate lexicographic prefixes below U64_MAX; never accept a larger value.
    bound = "18446744073709551615"
    branches = ["0", "[1-9][0-9]{0,18}", bound]
    for index, digit in enumerate(bound):
        low = 1 if index == 0 else 0
        high = int(digit) - 1
        if high >= low:
            token = str(low) if low == high else "[" + str(low) + "-" + str(high) + "]"
            branches.append(bound[:index] + token + "[0-9]{" + str(19-index) + "}")
    return string(20, 1, "^(?:" + "|".join(branches) + ")$")


D["AsciiId"] = string(64, 1, "^[a-z][a-z0-9.-]*$")
D["Feature"] = string(128, 4, "^[a-z][a-z0-9.-]*/v[1-9][0-9]*$")
D["Digest"] = string(71, 71, "^sha256:[0-9a-f]{64}$")
D["U64"] = decimal_u64()
D["MachineBinding"] = string(32, 32, "^[0-9a-f]{32}$")
D["Uuid"] = string(36, 36, "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
D["Path"] = {**string(4096, 1, "^/(?:[^/\u0000]+(?:/[^/\u0000]+)*)?$"),
             "not": {"pattern": "(?:^|/)\\.{1,2}(?:/|$)"},
             "$comment": "Canonical absolute UTF-8 lexical path. Symlink, mount and object-identity checks are outside S0. No Unicode normalization."}
STORE = "/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}"
D["StorePath"] = {"allOf": [ref("Path"), {"pattern": "^" + STORE + "$(?![\\s\\S])"}]}
D["StoreFile"] = {"allOf": [ref("Path"), {"pattern": "^" + STORE + "(?:/[^/]+)*$(?![\\s\\S])"}],
                  "$comment": "A store output or descendant; lexical syntax is not a closure or artifact verification."}
D["Text"] = string(4096, 0, "^[^\u0000]*$")
D["Argv"] = array(ref("Text"), maximum=256, ordered=True)
D["Features"] = array(ref("Feature"), maximum=256)
D["Ids"] = array(ref("AsciiId"))
D["Annotations"] = mapping(ref("AsciiId"), string(2048), 64)
D["EnvName"] = string(128, 1, "^[A-Za-z_][A-Za-z0-9_]*$")
D["LiteralEnv"] = mapping(ref("EnvName"), ref("Text"))
D["Inputs"] = obj({key: ref("Digest") for key in
                   ("flakeSourceDigest", "flakeLockDigest", "foreignLockDigest", "misaLibraryDigest")})
D["RootSelector"] = obj({"kind": enum("partuuid", "fsuuid", "luksuuid"), "value": ref("Uuid")},
    comment="Ch11 RootId and Ch12 selector concretization: lowercase persistent UUIDs, not /dev names or unauthenticated labels.")
D["StoreOrOCIRef"] = union(
    obj({"kind": {"const": "store"}, "path": ref("StorePath")}),
    obj({"kind": {"const": "oci"}, "layout": ref("Path"), "manifest": ref("Digest")}))
D["StoreOrOCIRef"]["$comment"] = "Ch11 tagged reference concretization: OCI layout plus manifest digest, or Nix store object holding an OCI layout; never a materialized-tree identity."
D["VerifiedRootRef"] = obj({"name": ref("AsciiId"),
    "platform": enum("linux/amd64", "linux/arm64", "linux/386"),
    "libcFamily": enum("glibc", "musl"), "digest": ref("Digest"),
    "sourceLockKey": ref("AsciiId"), "sealedPath": ref("StoreOrOCIRef"),
    "composeReceiptDigest": ref("Digest"), "qualification": {"const": "R1"}})
D["ForeignStorage"] = union(obj({"mode": {"const": "retain-all"}}),
    obj({"mode": {"const": "leased-gc"}, "minRetainSeconds": ref("U64"), "brokerPolicyDigest": ref("Digest")}))
D["ForeignStorage"]["$comment"] = "leased-gc has a complete wire form but S0 semantic validation rejects it with E_CAPABILITY: no qualified broker."
D["GrantSpec"] = union(*[obj({"id": ref("AsciiId"), "kind": {"const": kind},
    "source": ref("Path"), "target": ref("Path"), "writable": {"type": "boolean"}})
    for kind in ("file", "directory", "session-socket")])
D["GrantSpec"]["$comment"] = "Ch11 narrow host-grant concretization. source is the host path, target the application-view path. Semantic checks reject reserved host destinations and writable overlaps. Session sockets are explicit endpoints, not arbitrary device or network grants."
D["Desktop"] = obj({"id": string(255, 1, "^[A-Za-z][A-Za-z0-9._-]*\\.desktop$"),
    "entryDigest": ref("Digest"), "icons": array(obj({"path": ref("Path"), "digest": ref("Digest")})),
    "mime": array(string(255, 3, "^[A-Za-z0-9.+_-]+/[A-Za-z0-9.+_-]+$")),
    "dbusName": union({"type": "null"}, string(255, 3, "^[A-Za-z_][A-Za-z0-9_-]*(?:\\.[A-Za-z_][A-Za-z0-9_-]*)+$"))},
    comment="Ch15 desktop metadata concretized for declarative ExportSpec; this is not the runtime ExportRecord or resolved ExecSpec.")
D["ExportSpec"] = obj({"id": ref("AsciiId"), "name": ref("AsciiId"), "root": ref("Digest"),
    "program": ref("Path"), "argv": ref("Argv"), "env": ref("LiteralEnv"),
    "grants": ref("Ids"), "desktop": ref("Desktop")}, optional=("desktop",),
    comment="Ch11 ExportSpec concretization: id is the plan-local key; name is a host CLI name; root is an OCI manifest digest. grants references hostGrants IDs. Full-host v1 has no hostGrants and therefore requires empty grants. argv is ordered and never shell-expanded.")
D["KeyRef"] = obj({"keyId": ref("AsciiId"), "alg": {"const": "ed25519"},
    "publicKey": string(44, 44, "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")},
    comment="Ch16 KeyRef concretization: non-secret Ed25519 public key, canonical padded RFC4648 base64 of exactly 32 bytes; S0 does not verify signatures.")
D["PublisherKey"] = obj({"keyId": ref("AsciiId"), "alg": {"const": "ed25519"},
    "validFrom": integer(), "validUntil": integer(), "successorOf": ref("AsciiId"),
    "status": enum("active", "retiring", "revoked"), "revokedNotBefore": integer()},
    optional=("successorOf", "revokedNotBefore"),
    comment="Validity values are UTC Unix seconds. Ch16 publisher key IDs resolve through the root-owned key registry, not embedded private material. Semantic validation checks windows and rotation references.")
D["TrustPolicy"] = obj({"epoch": integer(),
    "nixSubstituters": array(obj({"url": string(2048, 9, "^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[^\\s?#]*)?$"),
        "publicKeys": array(ref("KeyRef"), 64, 1), "requireSigs": {"const": True}}), 64),
    "imagePublishers": mapping(ref("AsciiId"), array(ref("PublisherKey"), 64, 1)),
    "repoKeys": mapping(string(129, 3, "^[a-z][a-z0-9.-]*:[a-z][a-z0-9.-]*$"), array(ref("KeyRef"), 64, 1)),
    "channel": obj({"rootVersion": integer(1), "rootDigest": ref("Digest"),
        "thresholds": obj({role: integer(1, 64) for role in ("root", "targets", "snapshot", "timestamp")})}),
    "approvers": union(obj({"mode": {"const": "interactive"}, "threshold": {"const": 0}, "keys": {"type": "array", "maxItems": 0, "items": ref("KeyRef")}}),
        obj({"mode": {"const": "signed-by"}, "threshold": integer(1, 64), "keys": array(ref("KeyRef"), 64, 1)})),
    "time": obj({"source": {"const": "rtc+bounded-ntp"}, "floorEpoch": integer()})},
    comment="Ch16 proposed policy layout, closed. Threshold roles are concretized as root/targets/snapshot/timestamp; interactive approval has zero cryptographic threshold and no keys. Policy consistency is validated, not authenticity, freshness, enrollment, or approval.")
D["Scope"] = union(obj({"kind": {"const": "system"}}), obj({"kind": {"const": "user"}, "uid": integer(1, 4294967294)}))
D["Identity"] = obj({"uid": integer(0, 4294967294), "gid": integer(0, 4294967294)})
D["ServiceEnv"] = mapping(ref("EnvName"), union(obj({"kind": {"const": "literal"}, "value": ref("Text")}),
    obj({"kind": {"const": "secret"}, "secretId": ref("AsciiId")})))
D["Readiness"] = union(obj({"kind": {"const": "exec-started"}}),
    obj({"kind": {"const": "fd-newline"}, "fd": integer(3, 255), "timeout": integer(1, 86400)}),
    obj({"kind": {"const": "probe"}, "program": ref("Path"), "args": ref("Argv"), "timeout": integer(1, 86400)}))
D["Restart"] = union(obj({"kind": {"const": "never"}}), obj({"kind": {"const": "always"}}),
    obj({"kind": {"const": "on-failure"}, "burst": integer(1, 1000000), "window": integer(1, 86400), "delay": integer(0, 86400)}))
D["Stop"] = obj({"signal": enum("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"),
    "gracePeriod": integer(0, 86400), "killProcessGroup": {"type": "boolean"}})
D["Directory"] = obj({"path": ref("Path"), "owner": ref("Identity"),
    "mode": string(4, 4, "^0[0-7]{3}$"), "lifetime": enum("runtime", "persistent")})
D["Socket"] = obj({"id": ref("AsciiId"), "kind": enum("unix-stream", "unix-datagram"),
    "path": ref("Path"), "owner": ref("Identity"), "mode": string(4, 4, "^0[0-7]{3}$")})
D["BackendOptions"] = obj({"adapter": {"const": "dinit"}, "smoothRecovery": {"type": "boolean"}},
    comment="Ch13 names Dinit smooth-recovery. This optional closed extension requires service.backend.dinit/v1; S0 rejects that required feature rather than pretending to execute it.")
node = {"id": ref("AsciiId"), "kind": enum("longrun", "oneshot"), "scope": ref("Scope"),
        "requires": ref("Ids"), "wants": ref("Ids"), "after": ref("Ids"), "requiredFeatures": ref("Features")}
process = {**node, "command": ref("Path"), "argv": ref("Argv"), "cwd": ref("Path"), "env": ref("ServiceEnv"),
    "identity": ref("Identity"), "readiness": ref("Readiness"), "restart": ref("Restart"), "stop": ref("Stop"),
    "directories": array(ref("Directory")), "sockets": array(ref("Socket")),
    "capabilities": ref("Features"), "backendOptions": ref("BackendOptions")}
process_schema = obj(process, optional=("backendOptions",))
process_schema["allOf"] = [{"if": {"required": ["backendOptions"]},
    "then": {"properties": {"requiredFeatures": {"contains": {"const": "service.backend.dinit/v1"}}}}}]
D["ServiceSpec"] = union(process_schema, obj({**node, "kind": {"const": "milestone"}}))
D["ServiceSpec"]["$comment"] = "Ch4 and Ch13 concretization. Scope is tagged, timeout/window/delay/gracePeriod units are seconds, env values are tagged literals or secret references. A milestone has no process fields. No runtime backend implementation is asserted by accepting a schema."
D["ServiceGraph"] = obj({"services": array(ref("ServiceSpec")), "targets": mapping(ref("AsciiId"), ref("Ids"))},
    comment="Ch11 graph concretization: targets maps milestone IDs to member service IDs; nodes and all references are plan-local. requires and after participate in cycle checks; wants alone does not order.")
D["ProviderBinding"] = obj({"id": ref("AsciiId"), "provides": array(ref("Feature"), 256, 1),
    "requires": ref("Features"), "digest": ref("Digest")},
    comment="Ch11 concretization: each exact versioned capability has one exclusive provider; requirements resolve to provided capabilities. Provider id is also a service-graph node ID.")
D["OwnedMount"] = obj({"owner": ref("AsciiId"), "source": ref("Path"), "target": ref("Path"), "writable": {"type": "boolean"}},
    comment="Ch11 concretization: owner is hostId or a declared service/provider ID. Both paths are host paths. Exclusive writable ownership uses component boundaries, never string-prefix matching.")
D["UserSpec"] = obj({"name": ref("AsciiId"), "uid": integer(1, 4294967294), "gid": integer(1, 4294967294), "home": ref("Path")})
D["BackupPolicy"] = union(obj({"kind": {"const": "none"}}), obj({"kind": enum("snapshot", "app-quiesce+snapshot"), "retention": ref("AsciiId")}))
D["VolumeSpec"] = obj({"volumeId": ref("AsciiId"), "owner": ref("AsciiId"), "mountPath": ref("Path"),
    "consumers": ref("Ids"), "schemaEpoch": integer(), "backupPolicy": ref("BackupPolicy"),
    "writerGeneration": ref("Digest"), "migration": obj({"toEpoch": integer(), "program": ref("StoreFile"), "reversible": {"type": "boolean"}})},
    optional=("writerGeneration", "migration"),
    comment="Ch11/18 concretization adds explicit owner and mountPath; consumers and owner reference services. backupPolicy renders Ch18 backup policy. writerGeneration identifies a prior writer, never this plan's future self-hash. Migration requires explicit snapshot policy; S0 executes nothing.")
D["MountFlags"] = array(enum("ro", "rw", "nodev", "nosuid", "noexec", "noatime", "relatime", "sync"), 8)
D["FsType"] = enum("ext4", "btrfs", "xfs")
D["BootRoot"] = obj({"selector": ref("RootSelector"), "fstype": ref("FsType"), "mountFlags": ref("MountFlags")},
    comment="Filesystem enum is a syntactic S0 vocabulary, not recovery qualification for any driver. S0 does not boot.")
D["Unlock"] = union(obj({"method": {"const": "none"}, "luksUuid": {"type": "null"}, "mapperName": {"type": "null"},
    "tries": {"const": 0}, "timeoutSec": {"const": 0}, "allowDiscards": {"const": False}}),
    *[obj({"method": {"const": method}, "luksUuid": ref("Uuid"), "mapperName": ref("AsciiId"),
        "tries": integer(1, 99), "timeoutSec": integer(1, 86400), "allowDiscards": {"type": "boolean"},
        **({"keyFile": ref("Path")} if method == "keyfile" else {})}) for method in ("passphrase", "keyfile")])
D["Unlock"]["$comment"] = "Ch12 concretization: none has explicit null identifiers and zero retry/timeout values. keyfile additionally identifies a non-secret path, not key bytes. allowDiscards is explicit, never implicitly enabled."
D["Cmdline"] = obj({"template": array(string(4096, 1, "^[^\\s\u0000]+$"), 256, 1, ordered=True)},
    comment="Ordered kernel tokens. Semantic checks require exactly one misa.root=kind=value token (Ch12 H2), no misa.generation= token, and rendered byte length below kernel.cmdlineLimit including the appended generation token.")
D["Publisher"] = obj({"type": enum("bls1", "uki"), "titleKey": ref("AsciiId"), "sortKey": ref("AsciiId"),
    "rescue": {"type": "boolean"}, "selection": enum("counting", "oneshot", "manual"), "tries": integer(0, 99)})
D["Publisher"]["allOf"] = [{"if": {"properties": {"selection": {"const": "counting"}}, "required": ["selection"]},
    "then": {"properties": {"tries": integer(1, 99)}}, "else": {"properties": {"tries": {"const": 0}}}}]
D["HealthGate"] = enum("init-handoff", "base-target", "network", "user-session")
D["Health"] = obj({"gates": array(ref("HealthGate"), 4, 1),
    "bless": obj({"requires": array(ref("HealthGate"), 4, 1)}), "blessTimeoutSec": integer(1, 86400)})
D["Uki"] = obj({"recipeDigest": ref("Digest"),
    "profiles": array(obj({"id": integer(0, 255), "rescue": {"type": "boolean"}, "cmdline": ref("Cmdline")}), 256, 1),
    "signerPolicy": obj({"policyDigest": ref("Digest"), "keys": array(ref("KeyRef"), 64, 1), "threshold": integer(1, 64)})},
    comment="Ch12 UKI concretization: profile IDs are numeric, ordered ascending; each profile declares its command-line template and rescue role. signerPolicy is an immutable policy digest plus explicit public-key threshold. No derived UKI digest, ESP path, publication sequence or signing secret enters the generation body.")
uki_condition = {"if": {"properties": {"publisher": {"properties": {"type": {"const": "uki"}}, "required": ["type"]}}, "required": ["publisher"]},
                 "then": {"required": ["uki"]}, "else": {"not": {"required": ["uki"]}}}
D["BootPolicy"] = obj({"publisher": ref("Publisher"), "root": ref("BootRoot"), "unlock": ref("Unlock"),
    "cmdline": ref("Cmdline"), "health": ref("Health"), "uki": ref("Uki")}, optional=("uki",),
    comment="Ch11 names BootPolicy without a layout. This implementation uses the declarative subset of Ch12 BootRecord: publisher, root, unlock, cmdline, health and conditional UKI recipe. Built artifact metadata appears only in BootRecord.")
D["BootPolicy"]["allOf"] = [uki_condition]
artifact = {"store": ref("StoreFile"), "sha256": ref("Digest"), "size": ref("U64")}
D["KernelRelease"] = string(128, 1, "^[A-Za-z0-9][A-Za-z0-9._+-]*$")
D["BootRecord"] = obj({"schema": {"const": "misa.boot/v1"}, "platform": obj({"arch": enum("x86_64", "aarch64")}),
    "kernel": obj({**artifact, "uname": ref("KernelRelease"), "cmdlineLimit": integer(256, 4096)}),
    "initrd": obj({"parts": array(obj({"role": enum("microcode", "main", "extra"), **artifact}), 64, 1, ordered=True), "buildId": ref("Digest")}),
    "cmdline": ref("Cmdline"), "root": ref("BootRoot"), "unlock": ref("Unlock"),
    "mounts": array(obj({"source": ref("RootSelector"), "target": ref("Path"), "fstype": ref("FsType"), "mountFlags": ref("MountFlags")})),
    "init": obj({"path": ref("StoreFile"), "sha256": ref("Digest"), "elfMachine": enum(62, 183), "adapterId": ref("AsciiId"), "adapterBuildId": ref("Digest")}),
    "modules": obj({"dir": ref("StoreFile"), "uname": ref("KernelRelease"), "initrdOrder": array(string(128, 1, "^[A-Za-z0-9_][A-Za-z0-9_-]*$"), 1024, ordered=True)}),
    "firmware": obj({"dir": ref("StoreFile"), "initrdFiles": array(ref("Path"), 4096)}),
    "publisher": ref("Publisher"), "uki": ref("Uki"), "health": ref("Health")}, optional=("uki",),
    comment="Complete Ch12 boot fields. Extra mounts use persistent selectors; firmware initrdFiles are canonical absolute paths inside firmware.dir. Modules load order is semantically ordered. Boot metadata is schema-only: lexical paths and synthetic sizes/hashes prove no stored object, signature, or bootability.")
D["BootRecord"]["allOf"] = [uki_condition]

common = {"hostId": ref("AsciiId"), "inputs": ref("Inputs"), "roots": array(ref("VerifiedRootRef")),
    "exports": array(ref("ExportSpec")), "foreignStorage": ref("ForeignStorage"), "trust": ref("TrustPolicy"),
    "requiredFeatures": ref("Features"), "annotations": ref("Annotations")}
SCHEMAS = {
    "strata": obj({"schemaVersion": {"const": "misa.strata/v1"}, **common, "hostGrants": array(ref("GrantSpec"))}, optional=("annotations",)),
    "plan": obj({"schemaVersion": {"const": "misa.plan/v1"}, **common, "machineId": ref("MachineBinding"),
        "target": obj({"system": enum("x86_64-linux", "aarch64-linux"), "kernelArch": enum("x86_64", "aarch64"), "rootFs": ref("RootSelector")}),
        "host": obj({"topLevel": ref("StorePath"), "initrd": ref("StorePath"), "kernel": ref("StorePath"),
            "firmware": array(ref("StorePath")), "initAdapter": ref("AsciiId")}),
        "boot": ref("BootPolicy"), "serviceGraph": ref("ServiceGraph"), "providers": array(ref("ProviderBinding")),
        "mounts": array(ref("OwnedMount")), "users": array(ref("UserSpec")), "volumes": array(ref("VolumeSpec"))}, optional=("annotations",)),
    "generation": obj({"schemaVersion": {"const": "misa.generation/v1"}, "machineId": ref("MachineBinding"),
        "planDigest": ref("Digest"), "boot": ref("BootRecord"), "roots": array(ref("Digest")),
        "adapterIdentity": ref("Digest"), "requiredFeatures": ref("Features"), "generationId": ref("Digest")}),
}


def reachable_definitions(schema):
    names = set()

    def visit(value):
        if isinstance(value, dict):
            if "$ref" in value:
                name = value["$ref"].removeprefix("#/$defs/")
                if name not in names:
                    names.add(name)
                    visit(D[name])
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(schema)
    return {name: D[name] for name in sorted(names)}


def publish_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def synthetic_digest(label):
    return "sha256:" + hashlib.sha256(("misa-s0-synthetic-not-artifact:" + label).encode("ascii")).hexdigest()


def fixture_jcs(value):
    # These fixtures contain only ASCII keys/text, booleans, null and safe integers.
    # Thus this restricted encoder produces RFC8785 bytes; it is NOT a general JCS implementation.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record_digest(value):
    return "sha256:" + hashlib.sha256(fixture_jcs(value)).hexdigest()


def store(label):
    # Deterministic lexical Nix base32 name; deliberately not an existing derivation.
    alphabet = "0123456789abcdfghijklmnpqrsvwxyz"
    name = "".join(alphabet[b & 31] for b in hashlib.sha256(label.encode("ascii")).digest())
    return "/nix/store/" + name + "-synthetic-" + label


def fixtures():
    key = {"keyId": "synthetic-review", "alg": "ed25519",
           "publicKey": base64.b64encode(hashlib.sha256(b"misa-s0-synthetic-public-key-bytes-not-a-signer").digest()).decode("ascii")}
    inputs = {name: synthetic_digest(name) for name in D["Inputs"]["properties"]}
    root_digest = synthetic_digest("debian-oci-manifest")
    root = {"name": "debian", "platform": "linux/amd64", "libcFamily": "glibc", "digest": root_digest,
        "sourceLockKey": "debian", "sealedPath": {"kind": "oci", "layout": "/var/lib/misa/synthetic/oci/debian", "manifest": root_digest},
        "composeReceiptDigest": synthetic_digest("debian-compose-receipt"), "qualification": "R1"}
    export = {"id": "debian-hello", "name": "debian-hello", "root": root_digest, "program": "/usr/bin/printf",
        "argv": ["printf", "hello from synthetic Debian fixture\\n"], "env": {"LANG": "C.UTF-8"}, "grants": []}
    trust = {"epoch": 1, "nixSubstituters": [{"url": "https://cache.example.invalid/misa", "publicKeys": [key], "requireSigs": True}],
        "imagePublishers": {"debian": [{"keyId": key["keyId"], "alg": "ed25519", "validFrom": 1704067200,
            "validUntil": 1893456000, "status": "active"}]}, "repoKeys": {"apt:debian": [key]},
        "channel": {"rootVersion": 1, "rootDigest": synthetic_digest("channel-root"), "thresholds": {"root": 1, "targets": 1, "snapshot": 1, "timestamp": 1}},
        "approvers": {"mode": "interactive", "threshold": 0, "keys": []}, "time": {"source": "rtc+bounded-ntp", "floorEpoch": 1767225600}}
    provenance = {"fixture-provenance": "Synthetic S0 schema-only data. No OCI image, Nix closure, signing authority, boot artifact, or executable is provided or verified.",
        "fixture-hash-method": "Artifact digests are SHA-256 of ASCII misa-s0-synthetic-not-artifact: plus a stable label. Record digests hash restricted ASCII JCS bytes."}
    shared = {"hostId": "synthetic-workstation", "inputs": inputs, "roots": [root], "exports": [export],
        "foreignStorage": {"mode": "retain-all"}, "trust": trust, "requiredFeatures": [], "annotations": provenance}
    strata = {"schemaVersion": "misa.strata/v1", **deepcopy(shared), "hostGrants": [
        {"id": "workspace", "kind": "directory", "source": "/home/operator/workspace", "target": "/workspace", "writable": True}]}
    strata["exports"][0]["grants"] = ["workspace"]
    selector = {"kind": "fsuuid", "value": "913f2e4a-2b0d-4d71-9b24-97e0c4bfa193"}
    boot_root = {"selector": selector, "fstype": "ext4", "mountFlags": ["rw"]}
    unlock = {"method": "none", "luksUuid": None, "mapperName": None, "tries": 0, "timeoutSec": 0, "allowDiscards": False}
    cmdline = {"template": ["misa.root=fsuuid=" + selector["value"], "console=ttyS0,115200", "quiet"]}
    publisher = {"type": "bls1", "titleKey": "synthetic-workstation", "sortKey": "misa", "rescue": False, "selection": "manual", "tries": 0}
    health = {"gates": ["base-target", "init-handoff"], "bless": {"requires": ["base-target"]}, "blessTimeoutSec": 120}
    policy = {"root": boot_root, "unlock": unlock, "cmdline": cmdline, "publisher": publisher, "health": health}
    base_node = {"scope": {"kind": "system"}, "requires": [], "wants": [], "after": [], "requiredFeatures": []}
    log_service = {**deepcopy(base_node), "id": "log-sink", "kind": "longrun", "command": store("logger") + "/bin/misa-log",
        "argv": ["misa-log", "--foreground"], "cwd": "/", "env": {"LANG": {"kind": "literal", "value": "C.UTF-8"}},
        "identity": {"uid": 1000, "gid": 1000}, "readiness": {"kind": "exec-started"}, "restart": {"kind": "never"},
        "stop": {"signal": "SIGTERM", "gracePeriod": 10, "killProcessGroup": True}, "directories": [], "sockets": [],
        "capabilities": []}
    worker = deepcopy(log_service)
    worker.update({"id": "worker", "command": store("worker") + "/bin/misa-worker", "argv": ["misa-worker", "--foreground"], "requires": ["log-sink"]})
    milestone = {**deepcopy(base_node), "id": "base", "kind": "milestone", "requires": ["log-sink", "worker"]}
    machine = hashlib.sha256(b"misa-s0-synthetic-machine-binding").hexdigest()[:32]
    plan = {"schemaVersion": "misa.plan/v1", **deepcopy(shared), "machineId": machine,
        "target": {"system": "x86_64-linux", "kernelArch": "x86_64", "rootFs": selector},
        "host": {"topLevel": store("host"), "initrd": store("initrd"), "kernel": store("linux"), "firmware": [store("firmware")], "initAdapter": "dinit"},
        "boot": policy, "serviceGraph": {"services": [milestone, log_service, worker], "targets": {"base": ["log-sink", "worker"]}},
        "providers": [{"id": "log-sink", "provides": ["log.sink/v1"], "requires": [], "digest": synthetic_digest("log-provider")}],
        "mounts": [{"owner": "log-sink", "source": "/var/lib/misa/synthetic/log-source", "target": "/var/log/misa-synthetic", "writable": True}],
        "users": [{"name": "operator", "uid": 1000, "gid": 1000, "home": "/home/operator"}],
        "volumes": [{"volumeId": "worker-data", "owner": "worker", "mountPath": "/var/lib/misa/volumes/worker-data",
            "consumers": ["worker"], "schemaEpoch": 1, "backupPolicy": {"kind": "snapshot", "retention": "daily-seven"}}]}
    adapter_digest = synthetic_digest("dinit-adapter-build")
    boot = {"schema": "misa.boot/v1", "platform": {"arch": "x86_64"},
        "kernel": {"store": store("linux") + "/bzImage", "sha256": synthetic_digest("kernel-image"), "size": "12582912", "uname": "6.12.34-misa-synthetic", "cmdlineLimit": 2048},
        "initrd": {"parts": [
            {"role": "microcode", "store": store("microcode") + "/intel-ucode.img", "sha256": synthetic_digest("microcode-image"), "size": "3145728"},
            {"role": "main", "store": store("initrd") + "/initrd.img", "sha256": synthetic_digest("initrd-image"), "size": "33554432"}],
            "buildId": synthetic_digest("initrd-build-inputs")},
        **deepcopy(policy), "mounts": [],
        "init": {"path": store("dinit") + "/bin/dinit", "sha256": synthetic_digest("dinit-executable"), "elfMachine": 62,
            "adapterId": "dinit", "adapterBuildId": adapter_digest},
        "modules": {"dir": store("linux-modules") + "/lib/modules", "uname": "6.12.34-misa-synthetic", "initrdOrder": ["virtio_pci", "virtio_blk", "ext4"]},
        "firmware": {"dir": store("firmware") + "/lib/firmware", "initrdFiles": []}}
    body = {"schemaVersion": "misa.generation/v1", "machineId": machine, "planDigest": record_digest(plan), "boot": boot,
        "roots": [root_digest], "adapterIdentity": adapter_digest, "requiredFeatures": []}
    # Generation has no annotations authority escape hatch: synthetic provenance is
    # in the referenced plan and explicit synthetic names throughout its boot paths.
    generation = {**deepcopy(body), "generationId": record_digest(body)}
    return {"strata": strata, "plan": plan, "generation-body": body, "generation": generation}


def main():
    for domain, schema in SCHEMAS.items():
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://github.com/ZacharySF/misaos/schemas/misa." + domain + "-v1.schema.json",
            "title": "Misa " + domain + " v1 (S0 schema and semantic validation only)",
            "$comment": "Generated by schemas/generate.py from architecture baseline 1.4 Ch11/12/16. Authority domains have independent exact discriminators. Unknown properties fail closed. S0 supports no requiredFeatures and provides no boot, signature, image, or execution proof.",
            **schema, "$defs": reachable_definitions(schema)}
        publish_json(ROOT / "schemas" / ("misa." + domain + "-v1.schema.json"), schema)
    for name, fixture in fixtures().items():
        publish_json(ROOT / "fixtures" / (name + ".json"), fixture)


if __name__ == "__main__":
    main()
