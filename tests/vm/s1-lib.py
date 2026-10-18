# Helpers shared by the S1 oracle and the S1 acceptance test scripts. They are
# concatenated after a generated `S1 = json.loads(...)` header and run inside the
# NixOS test driver, where `machine` and `subtest` are provided as globals.
import hashlib
import json
import re
import shlex

STORE = S1["store"]
ADMISSION = "/home/alice/.config/misa/admission"
SHARE = "/home/alice/misa-s1-share"


def alice(command):
    """Run `command` as the unprivileged user in a login shell; raise on failure."""
    return machine.succeed("su - alice -c " + shlex.quote(command))


def alice_exec(command):
    """Run as alice and return (status, stdout, stderr) without raising."""
    status, out = machine.execute(
        "su - alice -c " + shlex.quote("{ " + command + "\n} 2>/tmp/s1-stderr")
    )
    err = machine.succeed("cat /tmp/s1-stderr; rm -f /tmp/s1-stderr")
    return status, out, err


def last_json(text):
    lines = [line for line in text.strip().splitlines() if line.strip()]
    return json.loads(lines[-1])


def key_values(text):
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def hex_of(digest):
    return digest.removeprefix("sha256:")


def normalized_import(record):
    """Preserve toolchain identity without embedding guest /nix/store paths in IFD JSON."""
    record["receipt"]["toolchain"] = {
        name: "sha256:" + hashlib.sha256(path.encode()).hexdigest()
        for name, path in record["receipt"]["toolchain"].items()
    }
    return record

def install_operator_key():
    """The local operator's admission key, independent of the publisher's."""
    machine.succeed(
        f"install -d -m700 -o alice -g users /home/alice/.config /home/alice/.config/misa {ADMISSION}",
        f"install -m600 -o alice -g users {S1['operator']['secret']} {ADMISSION}/secret.json",
        f"install -m644 -o alice -g users {S1['operator']['public']} {ADMISSION}/public.json",
    )


def approve_and_import(name):
    """Locally approve the exact lock, then import its layout; return the import record."""
    base = f"/home/alice/.config/misa/{name}"
    alice(
        f"misa strata approve --lock {S1['locks'][name]} "
        f"--secret-key {ADMISSION}/secret.json --output {base}.approval.json"
    )
    alice(
        f"misa strata import --lock {S1['locks'][name]} --approval {base}.approval.json "
        f"--trusted-key {ADMISSION}/public.json --name {name} --store {STORE} "
        f"--from-layout {S1['layouts'][name]} > {base}.import.json"
    )
    return normalized_import(json.loads(machine.succeed(f"cat {base}.import.json")))


def reimport_offline(name):
    """Re-verify and re-import exclusively from the retained store (no network, no layout)."""
    base = f"/home/alice/.config/misa/{name}"
    return normalized_import(
        json.loads(
            alice(
                f"misa strata import --lock {S1['locks'][name]} --approval {base}.approval.json "
                f"--trusted-key {ADMISSION}/public.json --name {name} --store {STORE} --offline"
            )
        )
    )


def store_list():
    return json.loads(alice(f"misa strata list --store {STORE}"))


def file_bytes(path_glob):
    """Independent byte count of every regular file under the glob, from the guest filesystem."""
    out = machine.succeed(
        "find " + path_glob + r" -type f -printf '%s\n' | awk '{s+=$1} END {print s+0}'"
    )
    return int(out.strip())


def tree_digest(hex_digest):
    """Digest of all regular files (path and content) of one retained materialization."""
    return machine.succeed(
        f"cd {STORE}/materialized/{hex_digest}/rootfs && "
        r"find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum"
    ).split()[0]


def bwrap_roots(needle):
    """Materialization digests bound read-only as `/` by running sandboxes whose argv contains needle."""
    out = machine.succeed("ps -ewwo args | grep '[b]wrap' || true")
    roots = set()
    for line in out.splitlines():
        if needle not in line:
            continue
        match = re.search(r"--ro-bind \S*/materialized/([0-9a-f]{64})/rootfs /(?:\s|$)", line)
        if match:
            roots.add(match.group(1))
    return roots


def heartbeat():
    text = machine.succeed(f"cat {SHARE}/heartbeat").strip()
    match = re.fullmatch(r"release=(\d+) tick=(\d+)", text)
    assert match, f"unexpected heartbeat {text!r}"
    return match.group(1), int(match.group(2))


def wrapper_invocation(command):
    """Parse the launcher invocation the NixOS module generated for a per-user command."""
    wrapper = alice(f"readlink -f $(command -v {command})").strip()
    text = machine.succeed(f"cat {wrapper}")
    match = re.search(
        r"(\S+/bin/misa) run --plan (\S+) --store (\S+) --export (\S+) --publisher-keyring (\S+)",
        text,
    )
    assert match, f"wrapper {wrapper} does not invoke the real launcher:\n{text}"
    return {
        "wrapper": wrapper,
        "text": text,
        "misa": match.group(1),
        "plan": match.group(2),
        "store": match.group(3),
        "export": match.group(4),
        "keyring": match.group(5),
    }


def wait_for_session():
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_x()
    # The cookie file survives reboots; only a running session proves it is the fresh one.
    machine.wait_until_succeeds("pgrep -u alice icewm")
    machine.wait_for_file("/home/alice/.Xauthority")
    machine.succeed("xauth merge /home/alice/.Xauthority")
    # Server-interpreted local-user access, so the X server accepts the sandboxed client
    # even if the cookie's host entry differs inside the sandbox's namespaces.
    alice("DISPLAY=:0 XAUTHORITY=/home/alice/.Xauthority xhost +SI:localuser:alice")


def launch_desktop_entry(entry_id):
    alice(
        "DISPLAY=:0 XAUTHORITY=/home/alice/.Xauthority "
        f"gio launch /etc/profiles/per-user/alice/share/applications/{entry_id} "
        ">/tmp/s1-gio.log 2>&1 &"
    )


def assert_offline():
    status, _ = machine.execute("timeout 6 bash -c 'echo > /dev/tcp/1.1.1.1/443'")
    assert status != 0, "the guest unexpectedly reached the public internet"
