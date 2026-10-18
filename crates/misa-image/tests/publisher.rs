use ed25519_dalek::SigningKey;
use misa_image::model::{self, Descriptor, ForeignLock, Limits, LockedImage};
use misa_image::publisher::{self, PublisherKey};
use misa_image::store::Store;
use misa_image::tools::Tools;
use misa_image::trust::{self, AuthorizedLock};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const SOURCE: &str = "ghcr.io/misa-project/debian";
const ALIAS: &str = "misa-fixture";
const FROM: u64 = 1_700_000_000;
const UNTIL: u64 = 4_102_444_800;
const NOW: u64 = 1_800_000_000;

struct Sandbox(tempfile::TempDir);
impl Sandbox {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }
    fn path(&self) -> &Path {
        self.0.path()
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        // Test-owned ephemeral roots only: restore directory access for TempDir cleanup.
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

fn key(seed: u8) -> (trust::SecretKey, trust::PublicKey) {
    let bytes = [seed; 32];
    let secret = trust::parse_secret_key(
        &serde_json::to_vec(&json!({
            "schemaVersion":"misa.ed25519-secret/v1", "secretSeed":hex::encode(bytes)
        }))
        .unwrap(),
    )
    .unwrap();
    let public = trust::PublicKey {
        schema_version: "misa.ed25519-public/v1".into(),
        public_key: hex::encode(SigningKey::from_bytes(&bytes).verifying_key().as_bytes()),
    };
    (secret, public)
}

fn record(alias: &str, public: &trust::PublicKey, status: &str) -> PublisherKey {
    publisher::key_record(alias, public, FROM, UNTIL, status).unwrap()
}

fn keyring(root: &Path, name: &str, records: &[PublisherKey], writable: bool) -> PathBuf {
    let dir = root.join(name);
    fs::create_dir(&dir).unwrap();
    for record in records {
        let path = dir.join(format!("{}.json", record.key_id));
        fs::write(&path, publisher::key_record_bytes(record).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    }
    let mode = if writable { 0o755 } else { 0o555 };
    fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
    dir
}

fn manifest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn statement(secret: &trust::SecretKey) -> publisher::PublisherStatement {
    publisher::sign_statement(SOURCE, &manifest('a'), "linux/amd64", ALIAS, secret).unwrap()
}

fn code(error: misa_image::Error) -> (&'static str, String) {
    (error.code, error.field)
}

fn local_lock() -> ForeignLock {
    ForeignLock {
        schema_version: 1,
        target_platform: "linux/amd64".into(),
        strata: BTreeMap::from([(
            "debian".into(),
            LockedImage {
                source: SOURCE.into(),
                image: Descriptor {
                    media_type: model::OCI_MANIFEST.into(),
                    digest: manifest('a'),
                    size: 512,
                },
                source_index: None,
                libc_family: "glibc".into(),
                limits: Limits::default(),
            },
        )]),
    }
}

#[test]
fn statement_binds_source_manifest_platform_and_key_alias() {
    let temp = Sandbox::new();
    let (secret, public) = key(1);
    let ring = keyring(
        temp.path(),
        "ring",
        &[record(ALIAS, &public, "active")],
        false,
    );
    let original = statement(&secret);
    let verified = publisher::verify_statement(original.clone(), &ring, NOW).unwrap();
    assert_eq!(verified.statement(), &original);
    assert_eq!(verified.key().key_id, ALIAS);

    let mutations: [fn(&mut publisher::PublisherStatement); 5] = [
        |s| s.source = "ghcr.io/misa-project/other".into(),
        |s| s.manifest_digest = format!("sha256:{}", "b".repeat(64)),
        |s| s.platform = "linux/arm64".into(),
        |s| s.key_id = "other-key".into(),
        |s| {
            let flipped = if s.signature.starts_with('a') {
                'b'
            } else {
                'a'
            };
            s.signature.replace_range(0..1, &flipped.to_string());
        },
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_eq!(
            publisher::verify_statement(changed, &ring, NOW)
                .unwrap_err()
                .code,
            "E_TRUST"
        );
    }
}

#[test]
fn signature_is_pinned_to_external_key_and_domain_separated_from_local_admission() {
    let temp = Sandbox::new();
    let (secret, _) = key(1);
    let (_, other_public) = key(2);
    // Same alias, different key material: a substituted keyring cannot validate it.
    let substituted = keyring(
        temp.path(),
        "substituted",
        &[record(ALIAS, &other_public, "active")],
        false,
    );
    let error = publisher::verify_statement(statement(&secret), &substituted, NOW).unwrap_err();
    assert_eq!(code(error), ("E_TRUST", "statement.signature".into()));

    // A genuine local-admission signature, even from the same key, is not a publisher
    // statement: authority and signing domain differ.
    let (_, public) = key(1);
    let pinned = keyring(
        temp.path(),
        "pinned",
        &[record(ALIAS, &public, "active")],
        false,
    );
    let approval = trust::approve(&local_lock(), &secret).unwrap();
    let mut transplanted = statement(&secret);
    transplanted.signature = approval.signature.clone();
    assert_eq!(
        publisher::verify_statement(transplanted, &pinned, NOW)
            .unwrap_err()
            .field,
        "statement.signature"
    );
    let mut relabeled = serde_json::to_value(statement(&secret)).unwrap();
    relabeled["authority"] = json!("local-image-admission");
    assert_eq!(
        publisher::parse_statement(&serde_json::to_vec(&relabeled).unwrap())
            .unwrap_err()
            .field,
        "statement.authority"
    );
}

#[test]
fn keyring_status_window_identity_and_confinement_fail_closed() {
    let temp = Sandbox::new();
    let (secret, public) = key(1);
    let stmt = statement(&secret);

    let active = keyring(
        temp.path(),
        "active",
        &[record(ALIAS, &public, "active")],
        false,
    );
    assert!(publisher::verify_statement(stmt.clone(), &active, FROM).is_ok());
    assert_eq!(
        publisher::verify_statement(stmt.clone(), &active, FROM - 1)
            .unwrap_err()
            .field,
        "publisherKey.validFrom"
    );
    assert_eq!(
        publisher::verify_statement(stmt.clone(), &active, UNTIL)
            .unwrap_err()
            .field,
        "publisherKey.validUntil"
    );

    let retiring = keyring(
        temp.path(),
        "retiring",
        &[record(ALIAS, &public, "retiring")],
        false,
    );
    assert!(publisher::verify_statement(stmt.clone(), &retiring, NOW).is_ok());

    let revoked = keyring(
        temp.path(),
        "revoked",
        &[record(ALIAS, &public, "revoked")],
        false,
    );
    assert_eq!(
        publisher::verify_statement(stmt.clone(), &revoked, NOW)
            .unwrap_err()
            .field,
        "publisherKey.status"
    );

    let writable = keyring(
        temp.path(),
        "writable",
        &[record(ALIAS, &public, "active")],
        true,
    );
    assert_eq!(
        publisher::verify_statement(stmt.clone(), &writable, NOW)
            .unwrap_err()
            .field,
        "keyring"
    );

    let empty = keyring(temp.path(), "empty", &[], false);
    assert_eq!(
        code(publisher::verify_statement(stmt.clone(), &empty, NOW).unwrap_err()),
        ("E_TRUST", "keyring".into())
    );
    assert_eq!(
        publisher::verify_statement(stmt.clone(), &temp.path().join("absent"), NOW)
            .unwrap_err()
            .code,
        "E_TRUST"
    );

    // The filename is lookup only; the body alias is authoritative.
    let mismatched = keyring(temp.path(), "mismatched", &[], false);
    let _ = fs::set_permissions(&mismatched, fs::Permissions::from_mode(0o700));
    let body = publisher::key_record_bytes(&record("another-key", &public, "active")).unwrap();
    let path = mismatched.join(format!("{ALIAS}.json"));
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&mismatched, fs::Permissions::from_mode(0o555)).unwrap();
    assert_eq!(
        publisher::verify_statement(stmt, &mismatched, NOW)
            .unwrap_err()
            .field,
        "publisherKey.keyId"
    );
}

#[test]
fn wire_records_are_closed_and_aliases_are_ascii_ids() {
    let (secret, public) = key(1);
    let good = serde_json::to_value(statement(&secret)).unwrap();
    for (field, replacement) in [("unknownPolicy", json!(true)), ("source", json!(null))] {
        let mut changed = good.clone();
        changed[field] = replacement;
        assert_eq!(
            publisher::parse_statement(&serde_json::to_vec(&changed).unwrap())
                .unwrap_err()
                .code,
            "E_SCHEMA"
        );
    }
    let mut tagged = good.clone();
    tagged["source"] = json!("ghcr.io/misa-project/debian:latest");
    assert!(publisher::parse_statement(&serde_json::to_vec(&tagged).unwrap()).is_err());
    let duplicate = serde_json::to_string(&good).unwrap().replacen(
        "\"authority\":\"image-publisher\"",
        "\"authority\":\"image-publisher\",\"authority\":\"image-publisher\"",
        1,
    );
    assert_eq!(
        publisher::parse_statement(duplicate.as_bytes())
            .unwrap_err()
            .code,
        "E_SCHEMA"
    );
    let too_long = "a".repeat(65);
    for alias in [
        "",
        "Upper",
        "1digit",
        "sha256:abc",
        "with_underscore",
        too_long.as_str(),
    ] {
        assert!(
            publisher::sign_statement(SOURCE, &manifest('a'), "linux/amd64", alias, &secret)
                .is_err(),
            "{alias:?} must not be a publisher key id"
        );
        assert!(publisher::key_record(alias, &public, FROM, UNTIL, "active").is_err());
    }
    assert!(publisher::key_record(ALIAS, &public, UNTIL, FROM, "active").is_err());
    assert!(publisher::key_record(ALIAS, &public, FROM, UNTIL, "trusted").is_err());
    let mut unknown: Value = serde_json::from_slice(
        &publisher::key_record_bytes(&record(ALIAS, &public, "active")).unwrap(),
    )
    .unwrap();
    unknown["extra"] = json!(1);
    assert!(publisher::parse_key_record(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

// --- Store-level behavior: real extraction requires the pinned tools, as in storage.rs.

fn unprivileged() -> bool {
    if rustix::process::geteuid().as_raw() == 0 {
        eprintln!("publisher store test skipped: imports intentionally refuse UID 0");
        false
    } else {
        true
    }
}

fn runtime_tools() -> Option<Tools> {
    let tools = Tools {
        skopeo: std::env::var_os("MISA_TEST_SKOPEO").map(PathBuf::from)?,
        umoci: std::env::var_os("MISA_TEST_UMOCI").map(PathBuf::from)?,
        bwrap: std::env::var_os("MISA_TEST_BWRAP").map(PathBuf::from)?,
    };
    assert!(
        [&tools.skopeo, &tools.umoci, &tools.bwrap]
            .into_iter()
            .all(|p| p.is_file() && p.starts_with("/nix/store")),
        "MISA_TEST_* must designate real pinned Nix binaries; no mock executables"
    );
    Some(tools)
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

fn layer() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(0);
    builder.append_data(&mut header, "bin", &[][..]).unwrap();
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(6);
    builder
        .append_data(&mut header, "bin/hello", &b"hello\n"[..])
        .unwrap();
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

/// A Debian-derived-shaped OCI fixture under a publisher-controlled repository, admitted
/// locally by `operator` (a key unrelated to any publisher).
fn fixture(layout: &Path, operator: &trust::SecretKey, public: trust::PublicKey) -> AuthorizedLock {
    fs::create_dir_all(layout.join("blobs/sha256")).unwrap();
    fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let layer_bytes = layer();
    let layer = blob(layout, &layer_bytes, model::OCI_TAR);
    let config = serde_json::to_vec(&json!({
        "architecture":"amd64", "os":"linux",
        "rootfs":{"type":"layers","diff_ids":[misa_plan::hash_bytes(&layer_bytes)]},
        "config":{}
    }))
    .unwrap();
    let config = blob(layout, &config, model::OCI_CONFIG);
    let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":model::OCI_MANIFEST,
        "config":wire(&config),"layers":[wire(&layer)] }))
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
                source: SOURCE.into(),
                image: manifest,
                source_index: Some(source_index),
                libc_family: "glibc".into(),
                limits: Limits::default(),
            },
        )]),
    };
    let approval = trust::approve(&lock, operator).unwrap();
    trust::verify_approval(lock, approval, public).unwrap()
}

#[test]
fn publisher_proof_gates_launch_and_is_checked_offline_by_doctor() {
    if !unprivileged() {
        return;
    }
    let Some(tools) = runtime_tools() else {
        eprintln!(
            "publisher store test skipped: set MISA_TEST_SKOPEO, MISA_TEST_UMOCI and MISA_TEST_BWRAP"
        );
        return;
    };
    let temp = Sandbox::new();
    let layout = temp.path().join("layout");
    let (operator_secret, operator_public) = key(9);
    let authorized = fixture(&layout, &operator_secret, operator_public.clone());
    let store_path = temp.path().join("store");
    let store = Store::open(&store_path).unwrap();
    let receipt = store
        .import(&authorized, "debian", &layout, &tools)
        .unwrap();
    let digest = receipt.manifest_digest.clone();

    let (publisher_secret, publisher_public) = key(3);
    let ring = keyring(
        temp.path(),
        "ring",
        &[record(ALIAS, &publisher_public, "active")],
        false,
    );

    // Locally admitted, unsigned roots (the Docker official situation) import and pass
    // doctor, but have no proof and can never launch.
    assert_eq!(store.doctor(&tools).unwrap().qualified_publishers, 0);
    let unsigned = store
        .launch_root_at(&digest, "debian", ALIAS, &ring, NOW)
        .unwrap_err();
    assert_eq!(code(unsigned), ("E_TRUST", "publisher.proof".into()));

    let signed =
        publisher::sign_statement(SOURCE, &digest, "linux/amd64", ALIAS, &publisher_secret)
            .unwrap();
    let verified = publisher::verify_statement(signed.clone(), &ring, NOW).unwrap();

    // Exact imported name/source/manifest binding.
    let other_digest = manifest('b');
    assert_eq!(
        code(
            store
                .qualify_publisher(&verified, "debian", SOURCE, &other_digest)
                .unwrap_err()
        ),
        ("E_TRUST", "statement.binding".into())
    );
    assert_eq!(
        code(
            store
                .qualify_publisher(&verified, "debian", "ghcr.io/misa-project/other", &digest)
                .unwrap_err()
        ),
        ("E_TRUST", "statement.binding".into())
    );
    assert_eq!(
        code(
            store
                .qualify_publisher(&verified, "other", SOURCE, &digest)
                .unwrap_err()
        ),
        ("E_TRUST", "publisher.binding".into())
    );
    // A local approval key relabeled as publisher is refused even though its signature
    // and a keyring pin are otherwise well formed.
    let relabel_ring = keyring(
        temp.path(),
        "relabel",
        &[record("misa-operator", &operator_public, "active")],
        false,
    );
    let relabeled = publisher::verify_statement(
        publisher::sign_statement(
            SOURCE,
            &digest,
            "linux/amd64",
            "misa-operator",
            &operator_secret,
        )
        .unwrap(),
        &relabel_ring,
        NOW,
    )
    .unwrap();
    assert_eq!(
        code(
            store
                .qualify_publisher(&relabeled, "debian", SOURCE, &digest)
                .unwrap_err()
        ),
        ("E_TRUST", "publisher.key".into())
    );
    assert_eq!(store.list().unwrap().qualified_publishers, 0);

    let proof = store
        .qualify_publisher(&verified, "debian", SOURCE, &digest)
        .unwrap();
    assert_eq!(proof.key_id, ALIAS);
    assert_eq!(proof.manifest_digest, digest);
    assert_eq!(
        store
            .qualify_publisher(&verified, "debian", SOURCE, &digest)
            .unwrap(),
        proof,
        "requalification verifies the retained proof rather than replacing it"
    );
    assert_eq!(store.doctor(&tools).unwrap().qualified_publishers, 1);
    let root = store
        .launch_root_at(&digest, "debian", ALIAS, &ring, NOW)
        .unwrap();
    assert_eq!(root, Path::new(&receipt.root_path));
    assert_eq!(fs::read(root.join("bin/hello")).unwrap(), b"hello\n");

    // Keyring policy is re-read on every launch; no state changes at launch.
    let revoked = keyring(
        temp.path(),
        "revoked",
        &[record(ALIAS, &publisher_public, "revoked")],
        false,
    );
    assert_eq!(
        store
            .launch_root_at(&digest, "debian", ALIAS, &revoked, NOW)
            .unwrap_err()
            .field,
        "publisherKey.status"
    );
    assert_eq!(
        store
            .launch_root_at(&digest, "debian", ALIAS, &ring, UNTIL)
            .unwrap_err()
            .field,
        "publisherKey.validUntil"
    );
    assert_eq!(
        store
            .launch_root_at(&digest, "debian", ALIAS, &ring, FROM - 1)
            .unwrap_err()
            .field,
        "publisherKey.validFrom"
    );
    let (_, substituted_public) = key(4);
    let substituted = keyring(
        temp.path(),
        "substituted",
        &[record(ALIAS, &substituted_public, "active")],
        false,
    );
    assert_eq!(
        code(
            store
                .launch_root_at(&digest, "debian", ALIAS, &substituted, NOW)
                .unwrap_err()
        ),
        ("E_TRUST", "publisher.key".into())
    );
    let absent = keyring(temp.path(), "absent-key", &[], false);
    assert_eq!(
        store
            .launch_root_at(&digest, "debian", ALIAS, &absent, NOW)
            .unwrap_err()
            .field,
        "keyring"
    );
    // Wrong manifest, stratum, or alias never reuse another root's proof.
    for (manifest_digest, name, alias) in [
        (other_digest.as_str(), "debian", ALIAS),
        (digest.as_str(), "debian2", ALIAS),
        (digest.as_str(), "debian", "misa-operator"),
    ] {
        assert!(
            store
                .launch_root_at(manifest_digest, name, alias, &relabel_ring, NOW)
                .is_err()
        );
        assert!(
            store
                .launch_root_at(manifest_digest, name, alias, &ring, NOW)
                .is_err()
        );
    }
    // The keyring is not a launch input a user-controlled store can supply.
    let inside = keyring(
        &store_path,
        "pinned-ring",
        &[record(ALIAS, &publisher_public, "active")],
        false,
    );
    assert_eq!(
        code(
            store
                .launch_root_at(&digest, "debian", ALIAS, &inside, NOW)
                .unwrap_err()
        ),
        ("E_TRUST", "keyring".into())
    );
    assert!(
        store
            .launch_root_at(&digest, "debian", ALIAS, &ring, NOW)
            .is_ok()
    );

    // Tampered retained evidence fails doctor and launch; nothing is repaired.
    let evidence = fs::read_dir(store_path.join("publishers"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let retained = evidence.join("statement.json");
    fs::set_permissions(&retained, fs::Permissions::from_mode(0o644)).unwrap();
    let mut forged = signed;
    forged.manifest_digest = other_digest;
    fs::write(&retained, serde_json::to_vec(&forged).unwrap()).unwrap();
    assert!(store.doctor(&tools).is_err());
    assert!(
        store
            .launch_root_at(&digest, "debian", ALIAS, &ring, NOW)
            .is_err()
    );
}
