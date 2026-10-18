# Stage 1 ("oracle"): perform the real local admission and import of every fixture
# image as the unprivileged user, on the same guest layout as the acceptance test
# (same uid, home, store path, pinned misa toolchain, byte-identical fixture
# images), and hand the actual `misa strata import` records back to Nix. The
# acceptance stage builds its immutable strata plans from these records and then
# proves, by importing again, that the receipts are reproduced exactly.
start_all()
machine.wait_for_unit("multi-user.target")
install_operator_key()

for name in ("debian-upstream", "debian-desktop-v1", "debian-desktop-v2"):
    with subtest(f"admit and import {name}"):
        record = approve_and_import(name)
        assert record["admissionAuthority"] == "local-image-admission", record
        assert record["publisherVerification"] == "not-performed", record
        assert record["verifiedRoot"]["name"] == name, record
        assert record["verifiedRoot"]["sourceLockKey"] == name, record
        assert record["receipt"]["rootPath"].startswith(STORE), record
        # Nix rejects JSON decoded from a derivation if it contains literal
        # untrusted /nix/store references. Hash the exact guest tool paths
        # in the shared helper, then export that comparison record; the
        # original signed receipt stays untouched in the user's store.
        machine.succeed(
            "printf '%s' "
            + shlex.quote(json.dumps(record, sort_keys=True, separators=(",", ":")))
            + f" > /tmp/{name}.import.json"
        )
        machine.copy_from_machine(f"/tmp/{name}.import.json")

with subtest("the retained store verifies offline"):
    alice(f"misa strata doctor --store {STORE}")
    listing = store_list()
    assert listing["retainedRoots"] == "3", listing
