# S2 helpers, concatenated after tests/vm/s1-lib.py: local admission and import of the
# merged lockset, whose single approval covers every root a two-ecosystem plan binds.
LOCKSET_APPROVAL = "/home/alice/.config/misa/lockset.approval.json"


def approve_lockset():
    alice(
        f"misa strata approve --lock {FIXTURE['locks']['lockset']} "
        f"--secret-key {ADMISSION}/secret.json --output {LOCKSET_APPROVAL}"
    )


def import_lockset(name, source):
    """Import one lockset entry; `source` is `--offline` or `--from-layout PATH`."""
    return normalized_import(
        json.loads(
            alice(
                f"misa strata import --lock {FIXTURE['locks']['lockset']} "
                f"--approval {LOCKSET_APPROVAL} --trusted-key {ADMISSION}/public.json "
                f"--name {name} --store {STORE} {source}"
            )
        )
    )


def from_layout(name):
    return f"--from-layout {FIXTURE['layouts'][name]}"
