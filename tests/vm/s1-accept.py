# Stage 2: the S1 acceptance scenario on stock NixOS with an ordinary user in a real
# graphical session (lightdm autologin + IceWM). Every claim below is asserted on
# observed behaviour of the real `misa` launcher, the real module output and the
# real X server, never on command success alone.
V1 = S1["expected"]["debian-desktop-v1"]
V2 = S1["expected"]["debian-desktop-v2"]
UP = S1["expected"]["debian-upstream"]
V1_HEX = hex_of(V1["verifiedRoot"]["digest"])
V2_HEX = hex_of(V2["verifiedRoot"]["digest"])
UP_HEX = hex_of(UP["verifiedRoot"]["digest"])
KEYID = S1["publisher"]["keyId"]
DESKTOP_ID = "misa-s1-xclock.desktop"
PROFILE = "/etc/profiles/per-user/alice"

start_all()
wait_for_session()

# ---------------------------------------------------------------------------
with subtest("the module renders the plan's exports for the declared user"):
    probe = wrapper_invocation("debian-probe")
    xclock = wrapper_invocation("debian-xclock")
    upstream = wrapper_invocation("upstream-probe")
    assert probe["plan"] == S1["plans"]["v1"], probe
    assert xclock["plan"] == S1["plans"]["v1"], xclock
    assert upstream["plan"] == S1["plans"]["upstream"], upstream
    assert probe["store"] == STORE and xclock["store"] == STORE, (probe, xclock)
    assert probe["export"] == "debian-probe" and xclock["export"] == "debian-xclock"
    assert probe["misa"] == S1["misa"] + "/bin/misa", probe
    assert probe["keyring"] == xclock["keyring"], "one pinned keyring per instance"

    # The pinned keyring holds exactly the independent publisher key, never the operator's.
    keyring_files = machine.succeed(f"ls {probe['keyring']}").split()
    assert keyring_files == [f"{KEYID}.json"], keyring_files
    record = json.loads(machine.succeed(f"cat {probe['keyring']}/{KEYID}.json"))
    assert record["keyId"] == KEYID and record["alg"] == "ed25519", record
    assert record["publicKey"] == S1["publisher"]["publicKey"], record
    operator = json.loads(machine.succeed(f"cat {S1['operator']['public']}"))
    assert record["publicKey"] != operator["publicKey"], "publisher and local admission keys must differ"
    assert record["status"] == "active", record

    # The plan the launcher reads is the immutable Nix-built, validated one.
    plan = json.loads(machine.succeed(f"cat {probe['plan']}"))
    assert plan["schemaVersion"] == "misa.strata/v1", plan
    assert [root["composeReceiptDigest"] for root in plan["roots"]] == [V1["receiptDigest"]], plan
    assert {e["id"]: e["root"] for e in plan["exports"]} == {
        "debian-probe": V1["verifiedRoot"]["digest"],
        "debian-xclock": V1["verifiedRoot"]["digest"],
    }, plan

    # The desktop entry launches the same real launcher, unprivileged, with no store scan.
    entry = machine.succeed(f"cat {PROFILE}/share/applications/{DESKTOP_ID}")
    assert f"Exec={probe['misa']} run --plan {probe['plan']} --store {STORE} --export debian-xclock" in entry, entry
    assert "X-MisaStrataExport=debian-xclock" in entry, entry
    assert "Terminal=false" in entry, entry

    # Another local account cannot probe this user's store through the wrapper.
    status, out = machine.execute(f"{probe['wrapper']} identity 2>&1")
    assert status == 1 and "scoped to user" in out, (status, out)

    # The module changes nothing of the host's init or boot and installs no service.
    machine.fail("systemctl cat misa-strata.service")
    machine.succeed("test ! -e /var/lib/misa")

# ---------------------------------------------------------------------------
with subtest("launching fails closed while nothing is imported"):
    status, out, err = alice_exec("debian-probe identity")
    assert status == 2 and out.strip() == "", (status, out, err)
    assert last_json(err)["code"], err

# ---------------------------------------------------------------------------
with subtest("separate local admission and import reproduce the oracle receipts exactly"):
    install_operator_key()
    for name, expected in (("debian-upstream", UP), ("debian-desktop-v1", V1)):
        fresh = approve_and_import(name)
        assert fresh == expected, (name, fresh, expected)
    # The plan's composeReceiptDigest is the digest of the receipt this guest just produced.
    assert V1["verifiedRoot"]["composeReceiptDigest"] == V1["receiptDigest"]
    listing = store_list()
    assert listing["retainedRoots"] == "2" and listing["retainedReceipts"] == "2", listing
    assert listing["incompleteStages"] == "0", listing
    # Local admission alone is not publisher trust: the record says so.
    assert V1["publisherVerification"] == "not-performed", V1

# ---------------------------------------------------------------------------
with subtest("a locally admitted root is not launchable without publisher qualification"):
    status, out, err = alice_exec("debian-probe identity")
    assert status == 2 and out.strip() == "", (status, out, err)
    refusal = last_json(err)
    assert refusal["code"] == "E_TRUST" and refusal["field"] == "publisher.proof", refusal

with subtest("publisher qualification rejects impersonation and mismatched bindings"):
    keyring = probe["keyring"]
    qualify = f"misa strata publisher-qualify --store {STORE} --publisher-keyring {keyring}"
    # Same alias, signature by an unrelated key.
    status, out, err = alice_exec(
        f"{qualify} --name debian-desktop-v1 --statement {S1['statements']['rogueV1']}"
    )
    assert status != 0 and out.strip() == "", (status, out, err)
    assert last_json(err)["code"] == "E_TRUST" and last_json(err)["field"] == "statement.signature", err
    # A genuine statement for another manifest cannot qualify this root.
    status, out, err = alice_exec(
        f"{qualify} --name debian-desktop-v1 --statement {S1['statements']['v2']}"
    )
    assert status != 0 and out.strip() == "", (status, out, err)
    assert last_json(err)["code"] == "E_TRUST" and last_json(err)["field"] == "publisher.binding", err
    # Nor can it qualify the unmodified Docker image, which has no publisher signature at all.
    status, out, err = alice_exec(
        f"{qualify} --name debian-upstream --statement {S1['statements']['v1']}"
    )
    assert status != 0 and out.strip() == "", (status, out, err)
    assert last_json(err)["code"] == "E_TRUST" and last_json(err)["field"] == "publisher.binding", err
    # Nothing above created a proof.
    status, out, err = alice_exec("debian-probe identity")
    assert status == 2 and last_json(err)["field"] == "publisher.proof", (status, out, err)

with subtest("the independent publisher key qualifies the exact manifest"):
    out = alice(f"{qualify} --name debian-desktop-v1 --statement {S1['statements']['v1']}")
    qualified = last_json(out)
    assert qualified["publisherVerification"] == "performed", qualified
    assert qualified["publisherAuthority"] == "image-publisher", qualified
    assert qualified["proof"]["manifestDigest"] == V1["verifiedRoot"]["digest"], qualified
    assert qualified["proof"]["keyId"] == KEYID, qualified

# ---------------------------------------------------------------------------
with subtest("CLI export: real Debian root, sanitized environment, exact arguments"):
    machine.succeed(
        "echo host-only > /home/alice/host-secret && chown alice:users /home/alice/host-secret",
        "test -d " + SHARE,
    )
    identity = key_values(alice("debian-probe identity"))
    assert identity["release"] == "1" and identity["os"] == "debian-12", identity
    assert identity["marker"] == "v1-only,", identity

    assert bwrap_roots("misa-probe") == set(), "no probe should still be running"

    args = alice("debian-probe args 'a b' '$HOME' ''")
    assert args.splitlines() == ["arg[0]=a b", "arg[1]=$HOME", "arg[2]=", "argc=3"], args

    leaked = alice("MISA_HOST_SECRET=leak XDG_RUNTIME_DIR=/run/user/1000 debian-probe env")
    environment = key_values(leaked)
    assert "MISA_HOST_SECRET" not in environment and "XDG_RUNTIME_DIR" not in environment, leaked
    assert "DISPLAY" not in environment and "SSH_AUTH_SOCK" not in environment, leaked
    assert environment["HOME"] == "/tmp" and environment["LANG"] == "C.UTF-8", leaked

with subtest("host paths outside the declared grants do not exist for the root"):
    hidden = [
        "/home/alice",
        "/home/alice/host-secret",
        "/home/alice/.Xauthority",
        "/home/alice/misa-s1-share",
        "/home/alice/.local/share/misa/roots",
        "/etc/misa-s1-host-canary",
        "/nix",
        "/nix/store",
        "/run/current-system",
        "/var/lib/misa",
        "/home/alice/.config/misa/admission/secret.json",
    ]
    status, out, err = alice_exec("debian-probe denied " + " ".join(hidden))
    assert status == 0, (status, out, err)
    assert out.splitlines() == [f"ABSENT {p}" for p in hidden], out
    # The one granted directory is the contrast: visible only at its declared target.
    status, out, err = alice_exec("debian-probe denied /mnt/share")
    assert status == 3 and out.strip() == "VISIBLE /mnt/share", (status, out, err)

with subtest("the sealed root is read-only and the writable grant reaches only its source"):
    status, out, err = alice_exec("debian-probe write-root")
    assert status == 0, (status, out, err)
    assert out.splitlines() == [
        "READONLY /usr/misa-write-test",
        "READONLY /etc/misa-write-test",
        "READONLY /misa-write-test",
    ], out
    machine.fail(f"test -e {STORE}/materialized/{V1_HEX}/rootfs/usr/misa-write-test")
    assert alice("debian-probe share-write granted-by-plan").strip() == "SHARE_WRITTEN"
    assert machine.succeed(f"cat {SHARE}/probe.txt").strip() == "granted-by-plan"

with subtest("an unsigned upstream Docker image stays unlaunchable even though its policy lists the key"):
    status, out, err = alice_exec("upstream-probe")
    assert status == 2 and out.strip() == "", (status, out, err)
    refusal = last_json(err)
    assert refusal["code"] == "E_TRUST" and refusal["field"] == "publisher.proof", refusal

# ---------------------------------------------------------------------------
with subtest("GUI export: a real Debian X client in the stock graphical session"):
    launch_desktop_entry(DESKTOP_ID)
    machine.wait_for_window("misa-s1-gui")
    machine.succeed("xprop -name misa-s1-gui WM_CLASS | grep -q XClock")
    machine.wait_until_succeeds("ps -eo comm | grep -qx xclock")
    assert bwrap_roots("xclock") == {V1_HEX}, bwrap_roots("xclock")
    machine.screenshot("s1-xclock-release-1")

# ---------------------------------------------------------------------------
with subtest("a long-lived export keeps its own materialization across upgrade"):
    alice("nohup debian-probe hold >/home/alice/hold.log 2>&1 &")
    machine.wait_until_succeeds(f"grep -q 'release=1 tick=' {SHARE}/heartbeat")
    assert bwrap_roots("misa-probe hold") == {V1_HEX}
    # Inspect the actual foreign dynamic linker and libc, not just /etc/os-release.
    # The launcher resolves this chain inside the root and /nix/store is unmounted.
    maps = machine.succeed("cat /proc/$(pgrep -u alice -x misa-probe)/maps")
    assert re.search(r"/ld-linux-x86-64\.so\.2(?:\s|$)", maps), maps
    assert re.search(r"/libc\.so\.6(?:\s|$)", maps), maps
    assert "/nix/store/" not in maps, maps
    release, tick_before = heartbeat()
    assert release == "1"
    machine.wait_until_succeeds(
        f"grep -qv 'tick={tick_before}$' {SHARE}/heartbeat"
    )
    before = {
        "v1": tree_digest(V1_HEX),
        "upstream": tree_digest(UP_HEX),
    }
    listing_one = store_list()
    blobs_before = file_bytes(f"{STORE}/oci/blobs/sha256")
    assert int(listing_one["retainedBlobBytes"]) == blobs_before, (listing_one, blobs_before)

    fresh = approve_and_import("debian-desktop-v2")
    assert fresh == V2, (fresh, V2)
    alice(f"{qualify} --name debian-desktop-v2 --statement {S1['statements']['v2']}")

    listing_two = store_list()
    assert listing_two["retainedRoots"] == "3" and listing_two["retainedReceipts"] == "3", listing_two
    assert listing_two["incompleteStages"] == "0", listing_two
    blobs_after = file_bytes(f"{STORE}/oci/blobs/sha256")
    assert int(listing_two["retainedBlobBytes"]) == blobs_after > blobs_before, (listing_two, blobs_after)
    v2_bytes = file_bytes(f"{STORE}/materialized/{V2_HEX}/rootfs")
    grown = int(listing_two["materializedBytes"]) - int(listing_one["materializedBytes"])
    assert v2_bytes * 98 // 100 <= grown <= v2_bytes * 110 // 100, (grown, v2_bytes)
    assert int(listing_two["materializedBytes"]) > int(listing_one["materializedBytes"])

    # Both versions are retained side by side; the old one is untouched and still launched.
    assert machine.succeed(f"cat {STORE}/materialized/{V1_HEX}/rootfs/etc/misa-fixture-release").strip() == "1"
    assert machine.succeed(f"cat {STORE}/materialized/{V2_HEX}/rootfs/etc/misa-fixture-release").strip() == "2"
    machine.fail(f"test -e {STORE}/materialized/{V1_HEX}/rootfs/usr/share/misa-fixture/v2-only")
    machine.succeed(f"test -e {STORE}/materialized/{V1_HEX}/rootfs/usr/share/misa-fixture/v1-only")
    machine.fail(f"test -e {STORE}/materialized/{V2_HEX}/rootfs/usr/share/misa-fixture/v1-only")
    machine.succeed(f"test -e {STORE}/materialized/{V2_HEX}/rootfs/usr/share/misa-fixture/v2-only")
    assert tree_digest(V1_HEX) == before["v1"], "retained release 1 changed during the import"
    assert alice("debian-probe identity").count("release=1") == 1, "still the release-1 plan"

    # Activate the declared upgrade: the same module, the upgraded immutable plan.
    machine.succeed(
        "/run/current-system/specialisation/upgraded/bin/switch-to-configuration test"
    )
    upgraded = wrapper_invocation("debian-probe")
    assert upgraded["plan"] == S1["plans"]["v2"], upgraded
    assert wrapper_invocation("debian-xclock")["plan"] == S1["plans"]["v2"]

    # The old process survived the import and the switch and still runs on release 1.
    machine.succeed("ps -ewwo args | grep -q '[m]isa-probe hold'")
    release, tick_after = heartbeat()
    machine.wait_until_succeeds(f"grep -qv 'tick={tick_after}$' {SHARE}/heartbeat")
    release, tick_later = heartbeat()
    assert release == "1" and tick_later > tick_before, (release, tick_before, tick_later)
    assert bwrap_roots("misa-probe hold") == {V1_HEX}
    machine.succeed("ps -eo comm | grep -qx xclock")
    machine.wait_for_window("misa-s1-gui")

    # New launches take the new root; both roots run at the same time.
    identity = key_values(alice("debian-probe identity"))
    assert identity["release"] == "2" and identity["marker"] == "v2-only,", identity
    launch_desktop_entry(DESKTOP_ID)
    machine.wait_until_succeeds("test $(ps -eo comm | grep -cx xclock) -ge 2")
    assert bwrap_roots("xclock") == {V1_HEX, V2_HEX}, bwrap_roots("xclock")
    machine.screenshot("s1-xclock-releases-1-and-2")

    # Unchanged policy: the unsigned upstream image is still refused after the switch.
    status, out, err = alice_exec("upstream-probe")
    assert status == 2 and last_json(err)["field"] == "publisher.proof", (status, out, err)

    alice(f"misa strata doctor --store {STORE}")
    after = {
        "v1": tree_digest(V1_HEX),
        "v2": tree_digest(V2_HEX),
        "upstream": tree_digest(UP_HEX),
    }
    assert after["v1"] == before["v1"] and after["upstream"] == before["upstream"], (before, after)
    listing_before_reboot = store_list()

# ---------------------------------------------------------------------------
with subtest("reboot: retained roots and proofs survive, offline relaunch works"):
    machine.shutdown()
    machine.start()
    wait_for_session()
    assert_offline()
    machine.fail("ps -ewwo args | grep -q '[m]isa-probe hold'")

    # The reboot returns to the booted generation: release-1 plan, retained release-1 root.
    booted = wrapper_invocation("debian-probe")
    assert booted["plan"] == S1["plans"]["v1"], booted
    assert store_list() == listing_before_reboot, "retained store changed across reboot"
    alice(f"misa strata doctor --store {STORE}")
    assert reimport_offline("debian-desktop-v1") == V1
    assert reimport_offline("debian-desktop-v2") == V2
    assert reimport_offline("debian-upstream") == UP
    assert tree_digest(V1_HEX) == after["v1"] and tree_digest(V2_HEX) == after["v2"]

    identity = key_values(alice("debian-probe identity"))
    assert identity["release"] == "1", identity
    launch_desktop_entry(DESKTOP_ID)
    machine.wait_for_window("misa-s1-gui")
    assert bwrap_roots("xclock") == {V1_HEX}, bwrap_roots("xclock")

    machine.succeed(
        "/run/current-system/specialisation/upgraded/bin/switch-to-configuration test"
    )
    assert wrapper_invocation("debian-probe")["plan"] == S1["plans"]["v2"]
    identity = key_values(alice("debian-probe identity"))
    assert identity["release"] == "2" and identity["marker"] == "v2-only,", identity
    launch_desktop_entry(DESKTOP_ID)
    machine.wait_until_succeeds("test $(ps -eo comm | grep -cx xclock) -ge 2")
    assert bwrap_roots("xclock") == {V1_HEX, V2_HEX}, bwrap_roots("xclock")
    machine.screenshot("s1-offline-after-reboot")

    status, out, err = alice_exec("upstream-probe")
    assert status == 2 and last_json(err)["field"] == "publisher.proof", (status, out, err)
    assert_offline()
