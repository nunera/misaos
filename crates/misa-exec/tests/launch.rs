//! End-to-end launcher behavior against a really imported, really
//! publisher-qualified retained store and the pinned bubblewrap: no mock tools,
//! no mock verifier. Tests skip (loudly) unless the pinned Nix tools are named,
//! exactly like the storage tests; they need unprivileged user namespaces.
#![cfg(target_arch = "x86_64")]
use misa_exec::{Request, run_with_bwrap};
use misa_image::{
    Tools,
    model::{self, Descriptor, ForeignLock, Limits, LockedImage},
    publisher,
    store::{ImportReceipt, Store},
    trust::{self, AuthorizedLock},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const NOW: u64 = 1_800_000_000;
const KEY_ID: &str = "vendor";

struct Sandbox(tempfile::TempDir);
impl Sandbox {
    fn path(&self) -> &Path {
        self.0.path()
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        // Test-owned ephemeral roots only: undo permission sealing so TempDir can clean up.
        for entry in walkdir::WalkDir::new(self.path())
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if entry.file_type().is_dir() {
                let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700));
            }
        }
    }
}

struct Pinned {
    tools: Tools,
}

fn pinned() -> Option<Pinned> {
    if rustix::process::geteuid().as_raw() == 0 {
        eprintln!("launch test skipped: imports intentionally refuse UID 0");
        return None;
    }
    let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
    let tools = Tools {
        skopeo: var("MISA_TEST_SKOPEO")?,
        umoci: var("MISA_TEST_UMOCI")?,
        bwrap: var("MISA_TEST_BWRAP")?,
    };
    assert!(
        [&tools.skopeo, &tools.umoci, &tools.bwrap]
            .into_iter()
            .all(|p| p.is_file() && p.starts_with("/nix/store")),
        "MISA_TEST_* must designate real pinned Nix binaries; no mock executables"
    );
    Some(Pinned { tools })
}

/// A static x86-64 ELF whose only behavior is `exit(code)`.
fn static_elf(code: u8) -> Vec<u8> {
    let machine_code = [
        0xbf, code, 0, 0, 0, // mov edi, code
        0xb8, 0x3c, 0, 0, 0, // mov eax, 60 (exit)
        0x0f, 0x05, // syscall
    ];
    let total = 64 + 56 + machine_code.len();
    let mut image = Vec::with_capacity(total);
    image.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    image.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    image.extend_from_slice(&0x3eu16.to_le_bytes()); // x86-64
    image.extend_from_slice(&1u32.to_le_bytes());
    image.extend_from_slice(&0x400078u64.to_le_bytes()); // entry
    image.extend_from_slice(&64u64.to_le_bytes()); // phoff
    image.extend_from_slice(&0u64.to_le_bytes()); // shoff
    image.extend_from_slice(&0u32.to_le_bytes()); // flags
    image.extend_from_slice(&64u16.to_le_bytes()); // ehsize
    image.extend_from_slice(&56u16.to_le_bytes()); // phentsize
    image.extend_from_slice(&1u16.to_le_bytes()); // phnum
    image.extend_from_slice(&[0u8; 6]); // shentsize, shnum, shstrndx
    image.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    image.extend_from_slice(&5u32.to_le_bytes()); // R+X
    image.extend_from_slice(&0u64.to_le_bytes()); // offset
    image.extend_from_slice(&0x400000u64.to_le_bytes()); // vaddr
    image.extend_from_slice(&0x400000u64.to_le_bytes()); // paddr
    image.extend_from_slice(&(total as u64).to_le_bytes()); // filesz
    image.extend_from_slice(&(total as u64).to_le_bytes()); // memsz
    image.extend_from_slice(&0x1000u64.to_le_bytes()); // align
    image.extend_from_slice(&machine_code);
    assert_eq!(image.len(), total);
    image
}

fn layer(exit_code: u8) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for directory in ["proc", "dev", "tmp", "run", "mnt", "mnt/share", "bin"] {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        builder
            .append_data(&mut header, directory, &[][..])
            .unwrap();
    }
    let program = static_elf(exit_code);
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(program.len() as u64);
    builder
        .append_data(&mut header, "bin/ok", &program[..])
        .unwrap();
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

fn blob(layout: &Path, bytes: &[u8], media_type: &str) -> Descriptor {
    let digest = misa_plan::hash_bytes(bytes);
    fs::write(
        layout
            .join("blobs/sha256")
            .join(model::digest_hex(&digest).unwrap()),
        bytes,
    )
    .unwrap();
    Descriptor {
        media_type: media_type.into(),
        digest,
        size: bytes.len() as u64,
    }
}

fn wire(descriptor: &Descriptor) -> Value {
    json!({"mediaType":descriptor.media_type,"digest":descriptor.digest,"size":descriptor.size})
}

fn fixture(layout: &Path, exit_code: u8) -> AuthorizedLock {
    fs::create_dir_all(layout.join("blobs/sha256")).unwrap();
    fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let layer_bytes = layer(exit_code);
    let layer = blob(layout, &layer_bytes, model::OCI_TAR);
    let config = serde_json::to_vec(&json!({
        "architecture":"amd64","os":"linux",
        "rootfs":{"type":"layers","diff_ids":[misa_plan::hash_bytes(&layer_bytes)]},
        "config":{}
    }))
    .unwrap();
    let config = blob(layout, &config, model::OCI_CONFIG);
    let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":model::OCI_MANIFEST,
        "config":wire(&config),"layers":[wire(&layer)]}))
    .unwrap();
    let manifest = blob(layout, &manifest, model::OCI_MANIFEST);
    let mut selected = wire(&manifest);
    selected["platform"] = json!({"os":"linux","architecture":"amd64"});
    selected["annotations"] = json!({"org.opencontainers.image.ref.name":"fixture"});
    let index = serde_json::to_vec(
        &json!({"schemaVersion":2,"mediaType":model::OCI_INDEX,"manifests":[selected]}),
    )
    .unwrap();
    let source_index = blob(layout, &index, model::OCI_INDEX);
    fs::write(layout.join("index.json"), index).unwrap();
    let lock = ForeignLock {
        schema_version: 1,
        target_platform: "linux/amd64".into(),
        strata: BTreeMap::from([(
            "debian".into(),
            LockedImage {
                source: "docker.io/library/debian".into(),
                image: manifest,
                source_index: Some(source_index),
                libc_family: "glibc".into(),
                limits: Limits::default(),
            },
        )]),
    };
    let (secret, public) = trust::generate_keypair().unwrap();
    let approval = trust::approve(&lock, &secret).unwrap();
    trust::verify_approval(lock, approval, public).unwrap()
}

struct World {
    temp: Sandbox,
    pinned: Pinned,
    store: PathBuf,
    keyring: PathBuf,
    plans: std::cell::Cell<u32>,
}

struct Imported {
    receipt: ImportReceipt,
    lock: ForeignLock,
}

impl World {
    fn new(pinned: Pinned) -> Self {
        let temp = Sandbox(tempfile::tempdir().unwrap());
        let store = temp.path().join("store");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let keyring = temp.path().join("keyring");
        fs::create_dir(&keyring).unwrap();
        Self {
            temp,
            pinned,
            store,
            keyring,
            plans: std::cell::Cell::new(0),
        }
    }

    /// Import a root whose only program exits with `exit_code`; optionally publisher-qualify it.
    fn import(&self, name: &str, exit_code: u8, qualify: Option<&trust::SecretKey>) -> Imported {
        let layout = self.temp.path().join(format!("layout-{name}"));
        let authorized = fixture(&layout, exit_code);
        let store = Store::open(&self.store).unwrap();
        let receipt = store
            .import(&authorized, "debian", &layout, &self.pinned.tools)
            .unwrap();
        if let Some(secret) = qualify {
            let locked = &authorized.lock().strata["debian"];
            let statement = publisher::sign_statement(
                &locked.source,
                &locked.image.digest,
                &authorized.lock().target_platform,
                KEY_ID,
                secret,
            )
            .unwrap();
            let verified = publisher::verify_statement(statement, &self.keyring, NOW).unwrap();
            store
                .qualify_publisher(&verified, "debian", &locked.source, &locked.image.digest)
                .unwrap();
        }
        Imported {
            receipt,
            lock: authorized.lock().clone(),
        }
    }

    fn pin_key(&self, public: &trust::PublicKey, status: &str) {
        let record =
            publisher::key_record(KEY_ID, public, 1_700_000_000, 1_900_000_000, status).unwrap();
        let path = self.keyring.join(format!("{KEY_ID}.json"));
        let _ = fs::set_permissions(&self.keyring, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_file(&path);
        fs::write(&path, publisher::key_record_bytes(&record).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&self.keyring, fs::Permissions::from_mode(0o555)).unwrap();
    }

    fn plan(&self, imported: &Imported, edit: impl FnOnce(&mut Value)) -> PathBuf {
        let mut plan: Value =
            serde_json::from_str(include_str!("../../../fixtures/strata.json")).unwrap();
        let digest = imported.lock.strata["debian"].image.digest.clone();
        plan["roots"][0] = json!({
            "composeReceiptDigest": misa_plan::hash_bytes(
                &serde_jcs::to_vec(&imported.receipt).unwrap()),
            "digest": digest,
            "libcFamily": "glibc",
            "name": "debian",
            "platform": "linux/amd64",
            "qualification": "R1",
            "sealedPath": {
                "kind": "oci",
                "layout": self.store.join("oci").to_str().unwrap(),
                "manifest": digest,
            },
            "sourceLockKey": "debian",
        });
        plan["exports"][0] = json!({
            "argv": ["ok"], "env": {}, "grants": [],
            "id": "debian-ok", "name": "debian-ok",
            "program": "/bin/ok", "root": digest,
        });
        plan["hostGrants"] = json!([]);
        plan["inputs"]["foreignLockDigest"] = json!(model::lock_digest(&imported.lock).unwrap());
        plan["trust"]["imagePublishers"] = json!({"debian": [{
            "alg": "ed25519", "keyId": KEY_ID, "status": "active",
            "validFrom": 1_700_000_000u64, "validUntil": 1_900_000_000u64,
        }]});
        edit(&mut plan);
        self.plans.set(self.plans.get() + 1);
        let path = self
            .temp
            .path()
            .join(format!("plan-{}.json", self.plans.get()));
        fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
        path
    }

    fn run(&self, plan: &Path, now: u64) -> misa_exec::Result<i32> {
        run_with_bwrap(
            &Request {
                plan: plan.into(),
                store: self.store.clone(),
                export: "debian-ok".into(),
                publisher_keyring: self.keyring.clone(),
            },
            &[],
            now,
            &self.pinned.tools.bwrap,
        )
    }
}

#[test]
fn a_qualified_root_runs_and_the_old_root_stays_launchable_after_an_upgrade() {
    let Some(pinned) = pinned() else {
        eprintln!("launch test skipped: set MISA_TEST_SKOPEO, MISA_TEST_UMOCI and MISA_TEST_BWRAP");
        return;
    };
    let world = World::new(pinned);
    let (secret, public) = trust::generate_keypair().unwrap();
    world.pin_key(&public, "active");
    let old = world.import("old", 7, Some(&secret));
    let old_plan = world.plan(&old, |_| {});
    assert_eq!(world.run(&old_plan, NOW).unwrap(), 7);

    // Retain-all: importing and qualifying an upgrade never disturbs the old root.
    let new = world.import("new", 8, Some(&secret));
    let new_plan = world.plan(&new, |_| {});
    assert_eq!(world.run(&new_plan, NOW).unwrap(), 8);
    assert_eq!(world.run(&old_plan, NOW).unwrap(), 7);
}

#[test]
fn forged_unqualified_unpinned_and_out_of_policy_launches_fail_closed() {
    let Some(pinned) = pinned() else {
        eprintln!("launch test skipped: set MISA_TEST_SKOPEO, MISA_TEST_UMOCI and MISA_TEST_BWRAP");
        return;
    };
    let world = World::new(pinned);
    let (secret, public) = trust::generate_keypair().unwrap();
    world.pin_key(&public, "active");
    let imported = world.import("v1", 7, Some(&secret));
    let code = |result: misa_exec::Result<i32>| result.expect_err("must fail closed").code;
    let other_digest = format!("sha256:{}", "ab".repeat(32));

    // Plan claims that do not match the retained evidence.
    let forged_receipt = world.plan(&imported, |plan| {
        plan["roots"][0]["composeReceiptDigest"] = json!(other_digest);
    });
    assert_eq!(code(world.run(&forged_receipt, NOW)), "E_LOCK");
    let forged_layout = world.plan(&imported, |plan| {
        plan["roots"][0]["sealedPath"]["layout"] = json!("/var/lib/misa/elsewhere/oci");
    });
    assert_eq!(code(world.run(&forged_layout, NOW)), "E_LOCK");
    let forged_lock = world.plan(&imported, |plan| {
        plan["inputs"]["foreignLockDigest"] = json!(other_digest);
    });
    assert_eq!(code(world.run(&forged_lock, NOW)), "E_LOCK");
    let forged_root = world.plan(&imported, |plan| {
        plan["roots"][0]["digest"] = json!(other_digest);
        plan["roots"][0]["sealedPath"]["manifest"] = json!(other_digest);
        plan["exports"][0]["root"] = json!(other_digest);
    });
    assert_eq!(code(world.run(&forged_root, NOW)), "E_LOCK");

    // A different key pinned under the same alias is not the key that signed.
    let honest = world.plan(&imported, |_| {});
    let (_, impostor) = trust::generate_keypair().unwrap();
    world.pin_key(&impostor, "active");
    assert_eq!(code(world.run(&honest, NOW)), "E_TRUST");
    world.pin_key(&public, "active");
    assert_eq!(world.run(&honest, NOW).unwrap(), 7);

    // Plan policy: revoked, expired, not-yet-valid, below the time floor, no policy.
    let revoked = world.plan(&imported, |plan| {
        plan["trust"]["imagePublishers"]["debian"][0]["status"] = json!("revoked");
    });
    assert_eq!(code(world.run(&revoked, NOW)), "E_TRUST");
    assert_eq!(
        code(world.run(&honest, 1_950_000_000)),
        "E_TRUST",
        "expired"
    );
    assert_eq!(
        code(world.run(&honest, 1_650_000_000)),
        "E_TRUST",
        "before window"
    );
    let floor = world.plan(&imported, |plan| {
        plan["trust"]["time"]["floorEpoch"] = json!(1_850_000_000u64);
    });
    assert_eq!(
        code(world.run(&floor, NOW)),
        "E_TRUST",
        "below trusted floor"
    );
    let no_policy = world.plan(&imported, |plan| {
        plan["trust"]["imagePublishers"] = json!({});
    });
    assert_eq!(code(world.run(&no_policy, NOW)), "E_TRUST");
    let disagrees = world.plan(&imported, |plan| {
        plan["trust"]["imagePublishers"]["debian"][0]["validUntil"] = json!(1_899_999_999u64);
    });
    assert_eq!(code(world.run(&disagrees, NOW)), "E_TRUST");

    // The keyring being revoked in the pinned source also refuses launch.
    world.pin_key(&public, "revoked");
    assert_eq!(code(world.run(&honest, NOW)), "E_TRUST");
    world.pin_key(&public, "active");

    // Declared program problems are typed and never fall back to the host.
    let missing = world.plan(&imported, |plan| {
        plan["exports"][0]["program"] = json!("/bin/absent");
    });
    assert_eq!(code(world.run(&missing, NOW)), "E_EXEC");
    let escape = world.plan(&imported, |plan| {
        plan["exports"][0]["program"] = json!("/bin/../../etc/passwd");
    });
    assert!(matches!(
        code(world.run(&escape, NOW)),
        "E_SCHEMA" | "E_ESCAPE"
    ));
    assert_eq!(
        world.run(&honest, NOW).unwrap(),
        7,
        "policy failures never poison a good plan"
    );

    // A locally admitted import with no publisher proof is not launchable.
    let unqualified = world.import("v2", 9, None);
    let unqualified_plan = world.plan(&unqualified, |_| {});
    assert_eq!(code(world.run(&unqualified_plan, NOW)), "E_TRUST");

    // An edited sealed tree is caught before anything runs.
    let program = world
        .store
        .join("materialized")
        .join(model::digest_hex(&imported.lock.strata["debian"].image.digest).unwrap())
        .join("rootfs/bin");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(program.join("ok"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(program.join("ok"), b"tampered").unwrap();
    assert_eq!(code(world.run(&honest, NOW)), "E_STATE");
}
