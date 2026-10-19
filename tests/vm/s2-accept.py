# Stage 2: the S2 second-ecosystem scenario on stock NixOS with an ordinary user.
# Every claim is asserted on observed behaviour of the real `misa` launcher, the real
# module output and each root's own package manager, never on command success alone.
SINGLE = S2["expected"]["single-debian"]
DEBIAN = S2["expected"]["lockset-debian"]
VOID = S2["expected"]["lockset-void"]
UPSTREAM = S2["expected"]["lockset-upstream"]
DEB_HEX = hex_of(DEBIAN["verifiedRoot"]["digest"])
VOID_HEX = hex_of(VOID["verifiedRoot"]["digest"])
UP_HEX = hex_of(UPSTREAM["verifiedRoot"]["digest"])
PACKAGES = S2["packages"]
LOCKSET_EXPORTS = ["debian-packages", "debian-probe", "void-glibc-true", "void-packages", "void-probe", "void-upstream"]


def host_state():
    """Digest of host /etc and /usr (metadata and content) plus the host Nix store database."""
    return machine.succeed(
        "{ find /etc /usr -xdev -printf '%y %m %U %G %s %T@ %p -> %l\\n' | sort; "
        "find /etc /usr -xdev -type f -exec sha256sum {} + | sort; "
        "nix-store --dump-db; } | sha256sum"
    ).split()[0]


def host_has_no_foreign_databases():
    machine.succeed("test ! -e /var/lib/dpkg && test ! -e /var/db/xbps && test ! -e /var/lib/pacman")


def hold_maps():
    return machine.succeed("cat /proc/$(pgrep -u alice -x misa-probe)/maps")


def stop_holds():
    machine.succeed("pkill -u alice -f 'misa-probe hold' || true")
    machine.wait_until_fails("ps -ewwo args | grep -q '[m]isa-probe hold'")
    # The next hold must prove itself with a fresh heartbeat, not this one.
    machine.succeed(f"rm -f {SHARE}/heartbeat")


def receipts():
    return {(r["name"], r["lockDigest"]) for r in store_list()["receipts"]}


def assert_lockset_exports():
    """The two-ecosystem plan: each root runs on its own loader against its own database."""
    identity = key_values(alice("debian-probe identity"))
    assert identity["os"] == "debian-12" and identity["release"] == "1", identity
    identity = key_values(alice("void-probe identity"))
    assert identity["os"] == "void-rolling" and identity["release"] == "1", identity
    assert identity["marker"] == "void-only," and identity["uid"] == "1000", identity

    dpkg = sorted(alice("debian-packages").splitlines())
    assert dpkg == PACKAGES["dpkg"], (dpkg, PACKAGES["dpkg"])
    xbps = sorted(line.split()[1] for line in alice("void-packages").splitlines())
    assert xbps == PACKAGES["xbps"], (xbps, PACKAGES["xbps"])

    status, out, err = alice_exec("debian-probe denied /var/db/xbps /usr/bin/xbps-query")
    assert status == 0 and out.splitlines() == ["ABSENT /var/db/xbps", "ABSENT /usr/bin/xbps-query"], (status, out, err)
    hidden = ["/var/lib/dpkg", "/usr/bin/dpkg-query", "/home/alice", "/nix/store", "/etc/static"]
    status, out, err = alice_exec("void-probe denied " + " ".join(hidden))
    assert status == 0 and out.splitlines() == [f"ABSENT {p}" for p in hidden], (status, out, err)

    # Musl root, glibc ELF: refused by the launcher's preflight, never executed.
    status, out, err = alice_exec("void-glibc-true")
    assert status == 2 and out.strip() == "", (status, out, err)
    refusal = last_json(err)
    assert refusal["code"] == "E_ABI" and refusal["field"] == "program", refusal
    assert "different libc family" in refusal["message"], refusal

    # The unmodified official Void image stays unlaunchable: no publisher signed it.
    status, out, err = alice_exec("void-upstream")
    assert status == 2 and out.strip() == "", (status, out, err)
    refusal = last_json(err)
    assert refusal["code"] == "E_TRUST" and refusal["field"] == "publisher.proof", refusal


start_all()
machine.wait_for_unit("multi-user.target")

# ---------------------------------------------------------------------------
with subtest("the booted plan exports only the previously imported Debian root"):
    probe = wrapper_invocation("debian-probe")
    assert probe["plan"] == S2["plans"]["debian"], probe
    assert wrapper_invocation("debian-packages")["plan"] == S2["plans"]["debian"]
    for command in ("void-probe", "void-packages"):
        status, _, _ = alice_exec(f"command -v {command}")
        assert status != 0, f"{command} must not exist before the lockset grows"
    plan = json.loads(machine.succeed(f"cat {probe['plan']}"))
    assert plan["inputs"]["foreignLockDigest"] == SINGLE["receipt"]["lockDigest"], plan
    host_has_no_foreign_databases()

# ---------------------------------------------------------------------------
with subtest("S1 state: the Debian root is admitted, qualified and running"):
    install_operator_key()
    assert approve_and_import("debian-desktop-v1") == SINGLE
    qualify = f"misa strata publisher-qualify --store {STORE} --publisher-keyring {probe['keyring']}"
    alice(f"{qualify} --name debian-desktop-v1 --statement {S2['statements']['debian']}")
    identity = key_values(alice("debian-probe identity"))
    assert identity["os"] == "debian-12", identity
    assert sorted(alice("debian-packages").splitlines()) == PACKAGES["dpkg"]

    alice("nohup debian-probe hold >/home/alice/hold.log 2>&1 &")
    machine.wait_until_succeeds(f"grep -q 'release=1 tick=' {SHARE}/heartbeat")
    assert bwrap_roots("misa-probe hold") == {DEB_HEX}
    maps = hold_maps()
    assert re.search(r"/ld-linux-x86-64\.so\.2(?:\s|$)", maps) and re.search(r"/libc\.so\.6(?:\s|$)", maps), maps
    debian_tree = tree_digest(DEB_HEX)
    listing_one = store_list()
    assert listing_one["retainedRoots"] == "1" and listing_one["retainedReceipts"] == "1", listing_one
    blobs_one = file_bytes(f"{STORE}/oci/blobs/sha256")

host_before_import = host_state()

# ---------------------------------------------------------------------------
with subtest("the grown lockset needs its own approval"):
    lockset = S2["locks"]["lockset"]
    status, out, err = alice_exec(
        f"misa strata import --lock {lockset} "
        "--approval /home/alice/.config/misa/debian-desktop-v1.approval.json "
        f"--trusted-key {ADMISSION}/public.json --name void-musl-v1 --store {STORE} "
        + from_layout("void-musl-v1")
    )
    assert status != 0 and out.strip() == "", (status, out, err)
    refusal = last_json(err)
    assert refusal["code"] == "E_TRUST" and refusal["field"] == "approval.lockDigest", refusal
    assert store_list()["retainedRoots"] == "1"

with subtest("the lockset reverifies Debian offline and imports Void beside it"):
    approve_lockset()
    assert import_lockset("debian-desktop-v1", "--offline") == DEBIAN
    assert import_lockset("void-musl-v1", from_layout("void-musl-v1")) == VOID
    assert import_lockset("void-musl-upstream", from_layout("void-musl-upstream")) == UPSTREAM
    # Same Debian root, new admitted lock: the old receipt and materialization stay.
    assert DEBIAN["verifiedRoot"]["digest"] == SINGLE["verifiedRoot"]["digest"]
    assert DEBIAN["receipt"]["lockDigest"] != SINGLE["receipt"]["lockDigest"]
    assert tree_digest(DEB_HEX) == debian_tree, "the retained Debian root changed"
    assert receipts() == {
        ("debian-desktop-v1", SINGLE["receipt"]["lockDigest"]),
        ("debian-desktop-v1", DEBIAN["receipt"]["lockDigest"]),
        ("void-musl-v1", VOID["receipt"]["lockDigest"]),
        ("void-musl-upstream", UPSTREAM["receipt"]["lockDigest"]),
    }, receipts()
    listing_two = store_list()
    assert listing_two["retainedRoots"] == "3" and listing_two["incompleteStages"] == "0", listing_two
    blobs_two = file_bytes(f"{STORE}/oci/blobs/sha256")
    assert int(listing_two["retainedBlobBytes"]) == blobs_two > blobs_one, (listing_two, blobs_two)
    assert int(listing_two["materializedBytes"]) > int(listing_one["materializedBytes"]), listing_two

with subtest("publisher qualification binds the exact Void manifest"):
    for name, statement in (
        ("void-musl-v1", S2["statements"]["debian"]),
        ("void-musl-upstream", S2["statements"]["void"]),
    ):
        status, out, err = alice_exec(f"{qualify} --name {name} --statement {statement}")
        assert status != 0 and out.strip() == "", (name, status, out, err)
        assert last_json(err)["field"] == "publisher.binding", (name, err)
    qualified = last_json(alice(f"{qualify} --name void-musl-v1 --statement {S2['statements']['void']}"))
    assert qualified["proof"]["manifestDigest"] == VOID["verifiedRoot"]["digest"], qualified

with subtest("admission and qualification wrote no host path"):
    assert host_state() == host_before_import, "host /etc, /usr or Nix database changed"
    host_has_no_foreign_databases()

# ---------------------------------------------------------------------------
with subtest("activating the lockset plan keeps the running Debian process"):
    machine.succeed("/run/current-system/specialisation/lockset/bin/switch-to-configuration test")
    for command in LOCKSET_EXPORTS:
        assert wrapper_invocation(command)["plan"] == S2["plans"]["lockset"], command
    plan = json.loads(machine.succeed(f"cat {S2['plans']['lockset']}"))
    assert [r["name"] for r in plan["roots"]] == ["debian-desktop-v1", "void-musl-upstream", "void-musl-v1"], plan
    assert {r["libcFamily"] for r in plan["roots"]} == {"glibc", "musl"}, plan
    assert plan["inputs"]["foreignLockDigest"] == VOID["receipt"]["lockDigest"], plan

    _, tick_before = heartbeat()
    machine.wait_until_succeeds(f"grep -qv 'tick={tick_before}$' {SHARE}/heartbeat")
    assert bwrap_roots("misa-probe hold") == {DEB_HEX}
    stop_holds()

host_before_launch = host_state()

with subtest("two ecosystems, two package databases, one plan"):
    # Debian's publisher proof is per name/manifest/key, so it carries over unchanged.
    assert_lockset_exports()

with subtest("the Void export runs on its own musl loader"):
    alice("nohup void-probe hold >/home/alice/void-hold.log 2>&1 &")
    machine.wait_until_succeeds(f"grep -q 'release=1 tick=' {SHARE}/heartbeat")
    assert bwrap_roots("misa-probe hold") == {VOID_HEX}
    maps = hold_maps()
    # Void's musl loader is libc.so itself; no glibc loader or Nix store object is mapped.
    assert re.search(r"/usr/lib/libc\.so(?:\s|$)", maps), maps
    assert "ld-linux" not in maps and "libc.so.6" not in maps, maps
    assert "/nix/store/" not in maps, maps
    stop_holds()

with subtest("launches wrote no host path and the store still verifies"):
    assert host_state() == host_before_launch, "host /etc, /usr or Nix database changed"
    host_has_no_foreign_databases()
    alice(f"misa strata doctor --store {STORE}")
    listing_before_reboot = store_list()

# ---------------------------------------------------------------------------
with subtest("reboot: every root, receipt and proof survives; offline relaunch works"):
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    assert_offline()

    assert wrapper_invocation("debian-probe")["plan"] == S2["plans"]["debian"]
    assert store_list() == listing_before_reboot, "retained store changed across reboot"
    alice(f"misa strata doctor --store {STORE}")
    assert reimport_offline("debian-desktop-v1") == SINGLE
    assert import_lockset("debian-desktop-v1", "--offline") == DEBIAN
    assert import_lockset("void-musl-v1", "--offline") == VOID
    assert import_lockset("void-musl-upstream", "--offline") == UPSTREAM
    assert tree_digest(DEB_HEX) == debian_tree

    assert key_values(alice("debian-probe identity"))["os"] == "debian-12"
    machine.succeed("/run/current-system/specialisation/lockset/bin/switch-to-configuration test")
    assert_lockset_exports()
    assert store_list() == listing_before_reboot, "offline relaunch changed the store"
    host_has_no_foreign_databases()
    assert_offline()
