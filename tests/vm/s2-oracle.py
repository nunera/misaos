# Stage 1 ("oracle"): the real local admissions and imports on the same guest layout
# as the acceptance test. First the Debian root under its own S1 lock (the previously
# imported state), then every entry of the merged lockset. The records go back to
# Nix, which builds the immutable plans; the acceptance stage must reproduce them.
start_all()
machine.wait_for_unit("multi-user.target")
install_operator_key()


def export(label, record):
    # Hash guest tool paths (shared helper) so Nix can decode the record via IFD.
    machine.succeed(
        "printf '%s' "
        + shlex.quote(json.dumps(record, sort_keys=True, separators=(",", ":")))
        + f" > /tmp/{label}.import.json"
    )
    machine.copy_from_machine(f"/tmp/{label}.import.json")


with subtest("admit and import the Debian root under its own lock"):
    record = approve_and_import("debian-desktop-v1")
    assert record["verifiedRoot"]["libcFamily"] == "glibc", record
    export("single-debian", record)

with subtest("admit the merged lockset and import all of its roots"):
    approve_lockset()
    debian = import_lockset("debian-desktop-v1", "--offline")
    void = import_lockset("void-musl-v1", from_layout("void-musl-v1"))
    upstream = import_lockset("void-musl-upstream", from_layout("void-musl-upstream"))
    for record in (debian, void, upstream):
        assert record["admissionAuthority"] == "local-image-admission", record
        assert record["publisherVerification"] == "not-performed", record
        assert record["receipt"]["rootPath"].startswith(STORE), record
    assert len({r["receipt"]["lockDigest"] for r in (debian, void, upstream)}) == 1
    assert void["verifiedRoot"]["libcFamily"] == "musl", void
    export("lockset-debian", debian)
    export("lockset-void", void)
    export("lockset-upstream", upstream)

with subtest("the retained store verifies offline"):
    alice(f"misa strata doctor --store {STORE}")
    listing = store_list()
    assert listing["retainedRoots"] == "3" and listing["retainedReceipts"] == "4", listing
