use misa_image::model::{self, Descriptor, ForeignLock, Limits, LockedImage};
use misa_image::store::Store;
use misa_image::tools::Tools;
use misa_image::trust::{self, AuthorizedLock};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

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
        // Test-owned ephemeral roots only: restore directory access so TempDir
        // can remove permission-sealed fixtures. Production has no such repair.
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

fn unprivileged() -> bool {
    if rustix::process::geteuid().as_raw() == 0 {
        eprintln!("storage test skipped: imports intentionally refuse UID 0");
        false
    } else {
        true
    }
}

fn pinned_tools() -> Option<Tools> {
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

fn runtime_tools() -> Option<Tools> {
    let tools = pinned_tools();
    if tools.is_none() {
        eprintln!(
            "real storage extraction test skipped: set MISA_TEST_SKOPEO, MISA_TEST_UMOCI and MISA_TEST_BWRAP to the pinned binaries"
        );
    }
    tools
}

// These real pinned paths are never executed by pre-extraction rejection tests.
fn unused_tools() -> Tools {
    Tools {
        skopeo: "/nix/store/1q00xflv022gsyi0sbq7q04nzy6qb5qf-skopeo-1.22.2/bin/skopeo".into(),
        umoci: "/nix/store/r97bjlmhp292x6pq069idsk1rz8lhlly-umoci-0.6.0/bin/umoci".into(),
        bwrap: "/nix/store/nnnh2ks97pxsv3cswhmvir8vzi0gc63m-bubblewrap-0.12.0/bin/bwrap".into(),
    }
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
fn layer(upgrade: bool) -> Vec<u8> {
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
    header.set_mode(if upgrade { 0o644 } else { 0o6755 });
    header.set_uid(0);
    header.set_gid(42);
    header.set_mtime(0);
    let bytes = if upgrade {
        &b"upgrade\n"[..]
    } else {
        &b"first\n"[..]
    };
    header.set_size(bytes.len() as u64);
    builder
        .append_data(
            &mut header,
            if upgrade {
                "bin/upgrade"
            } else {
                "bin/version"
            },
            bytes,
        )
        .unwrap();
    if !upgrade {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        header.set_link_name("/bin/version").unwrap();
        builder
            .append_data(&mut header, "version", &[][..])
            .unwrap();
    }
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

fn fixture(layout: &Path, upgrade: bool) -> AuthorizedLock {
    fs::create_dir_all(layout.join("blobs/sha256")).unwrap();
    fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let mut layers = vec![layer(false)];
    if upgrade {
        layers.push(layer(true));
    }
    let descriptors: Vec<_> = layers
        .iter()
        .map(|bytes| blob(layout, bytes, model::OCI_TAR))
        .collect();
    let config = serde_json::to_vec(&json!({
        "architecture":"amd64", "os":"linux",
        "rootfs":{"type":"layers","diff_ids":layers.iter().map(|bytes| misa_plan::hash_bytes(bytes)).collect::<Vec<_>>()},
        "config":{}
    })).unwrap();
    let config = blob(layout, &config, model::OCI_CONFIG);
    let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":model::OCI_MANIFEST,
        "config":wire(&config),"layers":descriptors.iter().map(wire).collect::<Vec<_>>() }))
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

#[test]
fn opening_requires_private_real_directory_and_exclusive_caller_lock() {
    let temp = Sandbox::new();
    let store_path = temp.path().join("store");
    if !unprivileged() {
        assert_eq!(Store::open(&store_path).err().unwrap().code, "E_PATH_OWNER");
        return;
    }
    fs::create_dir(&store_path).unwrap();
    fs::set_permissions(&store_path, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(Store::open(&store_path).err().unwrap().code, "E_PATH_OWNER");
    fs::set_permissions(&store_path, fs::Permissions::from_mode(0o700)).unwrap();
    let link = temp.path().join("linked-store");
    symlink(&store_path, &link).unwrap();
    assert_eq!(Store::open(&link).err().unwrap().code, "E_PATH_OWNER");
    let store = Store::open(&store_path).unwrap();
    assert_eq!(Store::open(&store_path).err().unwrap().code, "E_STATE");
    let status = store.list().unwrap();
    assert_eq!(status.retained_roots, 0);
    assert_eq!(status.retained_blob_bytes, 0);
    let wire = serde_json::to_value(status).unwrap();
    assert_eq!(wire["storageMode"], "retain-all");
    assert_eq!(wire["retainedRoots"], "0");
    let index: Value =
        serde_json::from_slice(&fs::read(store_path.join("oci/index.json")).unwrap()).unwrap();
    assert_eq!(index["schemaVersion"], 2);
    assert_eq!(index["mediaType"], model::OCI_INDEX);
    assert_eq!(index["manifests"], json!([]));
    drop(store);
    assert!(
        Store::open(&store_path)
            .unwrap()
            .doctor(&unused_tools())
            .is_ok()
    );
}

#[test]
fn corrupted_or_symlinked_source_never_publishes_a_root() {
    if !unprivileged() {
        return;
    }
    let temp = Sandbox::new();
    let source = temp.path().join("source");
    let authorized = fixture(&source, false);
    let manifest = source
        .join("blobs/sha256")
        .join(model::digest_hex(&authorized.lock().strata["debian"].image.digest).unwrap());
    let original = fs::read(&manifest).unwrap();
    let external = temp.path().join("external-manifest");
    fs::rename(&manifest, &external).unwrap();
    symlink(&external, &manifest).unwrap();
    let store = Store::open(&temp.path().join("store")).unwrap();
    assert!(
        store
            .import(&authorized, "debian", &source, &unused_tools())
            .is_err()
    );
    fs::remove_file(&manifest).unwrap();
    fs::write(&manifest, &original).unwrap();
    let mut changed = original.clone();
    changed[0] ^= 1;
    fs::write(&manifest, changed).unwrap();
    assert!(
        store
            .import(&authorized, "debian", &source, &unused_tools())
            .is_err()
    );
    let status = store.list().unwrap();
    assert_eq!(status.retained_roots, 0);
    assert_eq!(status.retained_manifests, 0);
    assert_eq!(status.retained_receipts, 0);
    assert_eq!(status.retained_blob_bytes, 0);
    assert_eq!(status.incomplete_stages, 2);
    assert_eq!(
        fs::read(external).unwrap(),
        original,
        "confined copy must not modify source or external bytes"
    );
}

#[test]
fn real_import_retains_roots_deduplicates_and_reopens_offline() {
    if !unprivileged() {
        return;
    }
    let Some(tools) = runtime_tools() else {
        return;
    };
    let temp = Sandbox::new();
    let first_source = temp.path().join("first");
    let second_source = temp.path().join("second");
    let first = fixture(&first_source, false);
    let second = fixture(&second_source, true);
    let store_path = temp.path().join("store");
    let store = Store::open(&store_path).unwrap();
    let first_receipt = store
        .import(&first, "debian", &first_source, &tools)
        .unwrap();
    assert_eq!(first_receipt.seal_mode, "read-only-permissions");
    assert_eq!(first_receipt.qualification, "R1");
    assert_eq!(first_receipt.stripped_modes, 1);
    let first_file = Path::new(&first_receipt.root_path).join("bin/version");
    assert_eq!(fs::read(&first_file).unwrap(), b"first\n");
    assert_eq!(
        fs::metadata(&first_file).unwrap().permissions().mode() & 0o7777,
        0o555
    );
    assert_eq!(
        fs::metadata(&first_file).unwrap().uid(),
        rustix::process::geteuid().as_raw()
    );
    let mut rootless = [0u8; 64];
    assert!(
        rustix::fs::lgetxattr(&first_file, "user.rootlesscontainers", &mut rootless[..]).unwrap()
            > 0,
        "umoci preserves inert bookkeeping for the original nonzero group"
    );
    assert_eq!(
        fs::write(&first_file, b"denied").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        fs::read_link(Path::new(&first_receipt.root_path).join("version")).unwrap(),
        Path::new("/bin/version")
    );
    let first_status = store.doctor(&tools).unwrap();
    assert_eq!(first_status.retained_roots, 1);
    let second_receipt = store
        .import(&second, "debian", &second_source, &tools)
        .unwrap();
    assert_ne!(first_receipt.tree_digest, second_receipt.tree_digest);
    assert_eq!(
        fs::read(&first_file).unwrap(),
        b"first\n",
        "upgrade preserves previous root bytes"
    );
    let second_status = store.doctor(&tools).unwrap();
    assert_eq!(second_status.retained_roots, 2);
    assert_eq!(second_status.retained_manifests, 2);
    assert_eq!(second_status.retained_receipts, 2);
    assert!(second_status.materialized_bytes > first_status.materialized_bytes);
    assert!(second_status.retained_blob_bytes > first_status.retained_blob_bytes);
    let mut expected_blobs = BTreeMap::new();
    for source in [&first_source, &second_source] {
        for entry in fs::read_dir(source.join("blobs/sha256")).unwrap() {
            let entry = entry.unwrap();
            let bytes = fs::read(entry.path()).unwrap();
            assert_eq!(
                fs::read(store_path.join("oci/blobs/sha256").join(entry.file_name())).unwrap(),
                bytes,
                "original manifest/index/config/layer bytes remain interoperable OCI blobs"
            );
            assert_ne!(
                entry.metadata().unwrap().ino(),
                fs::metadata(store_path.join("oci/blobs/sha256").join(entry.file_name()))
                    .unwrap()
                    .ino(),
                "external source inodes must never back retained CAS bytes"
            );
            expected_blobs.insert(entry.file_name(), bytes.len() as u64);
        }
    }
    assert_eq!(
        second_status.retained_blob_bytes,
        expected_blobs.values().sum::<u64>()
    );
    let repeated = store
        .import(&first, "debian", &store_path.join("oci"), &tools)
        .unwrap();
    assert_eq!(repeated, first_receipt);
    assert_eq!(store.list().unwrap().retained_receipts, 2);
    assert_eq!(store.list().unwrap().incomplete_stages, 0);
    drop(store);
    let reopened = Store::open(&store_path).unwrap();
    assert_eq!(reopened.doctor(&tools).unwrap().retained_roots, 2);
    // A second explicit authority may admit the same lock, but cannot mutate the
    // existing materialization or duplicate its content-addressed blobs.
    let (secret, public) = trust::generate_keypair().unwrap();
    let approval = trust::approve(first.lock(), &secret).unwrap();
    let another = trust::verify_approval(first.lock().clone(), approval, public).unwrap();
    reopened
        .import(&another, "debian", &store_path.join("oci"), &tools)
        .unwrap();
    let status = reopened.doctor(&tools).unwrap();
    assert_eq!(status.retained_roots, 2);
    assert_eq!(status.retained_receipts, 3);
    assert_eq!(
        status.retained_blob_bytes,
        second_status.retained_blob_bytes
    );
}

#[test]
fn real_doctor_detects_tree_blob_and_signature_tampering_without_repair() {
    if !unprivileged() {
        return;
    }
    let Some(tools) = runtime_tools() else {
        return;
    };
    let temp = Sandbox::new();
    let source = temp.path().join("source");
    let authorized = fixture(&source, false);
    let store_path = temp.path().join("store");
    let store = Store::open(&store_path).unwrap();
    let receipt = store
        .import(&authorized, "debian", &source, &tools)
        .unwrap();
    let file = Path::new(&receipt.root_path).join("bin/version");
    let original = fs::read(&file).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        store.doctor(&tools).is_err(),
        "writable cache is not sealed even before content changes"
    );
    fs::write(&file, b"other\n").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(
        store.doctor(&tools).is_err(),
        "same-length file tampering changes framed tree digest"
    );
    assert!(
        store
            .import(&authorized, "debian", &source, &tools)
            .is_err(),
        "reimport refuses, rather than repairs or overwrites, a tampered existing root"
    );
    assert_eq!(
        fs::read(&file).unwrap(),
        b"other\n",
        "doctor never repairs the cache"
    );
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&file, &original).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(store.doctor(&tools).is_ok());
    let mut rootless = [0u8; 64];
    let rootless_len =
        rustix::fs::lgetxattr(&file, "user.rootlesscontainers", &mut rootless[..]).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    rustix::fs::lsetxattr(
        &file,
        "user.rootlesscontainers",
        b"different",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(
        store.doctor(&tools).is_err(),
        "derived digest binds inert ownership metadata too"
    );
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    rustix::fs::lsetxattr(
        &file,
        "user.rootlesscontainers",
        &rootless[..rootless_len],
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    rustix::fs::lsetxattr(
        &file,
        "user.unexpected",
        b"denied",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(
        store.doctor(&tools).is_err(),
        "only helper-generated ownership metadata is allowed"
    );
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    rustix::fs::lremovexattr(&file, "user.unexpected").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(store.doctor(&tools).is_ok());
    let manifest = store_path
        .join("oci/blobs/sha256")
        .join(model::digest_hex(&receipt.manifest_digest).unwrap());
    let original_blob = fs::read(&manifest).unwrap();
    let mut changed = original_blob.clone();
    changed[0] ^= 1;
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&manifest, &changed).unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(store.doctor(&tools).is_err());
    assert!(
        store
            .import(&authorized, "debian", &source, &tools)
            .is_err()
    );
    assert_eq!(
        fs::read(&manifest).unwrap(),
        changed,
        "import must not overwrite an existing corrupt blob"
    );
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&manifest, original_blob).unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(store.doctor(&tools).is_ok());
    let evidence = fs::read_dir(store_path.join("receipts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let approval_path = evidence.join("approval.json");
    let mut approval: Value = serde_json::from_slice(&fs::read(&approval_path).unwrap()).unwrap();
    approval["signature"] = json!("00".repeat(64));
    fs::set_permissions(&approval_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&approval_path, serde_json::to_vec(&approval).unwrap()).unwrap();
    assert_eq!(store.doctor(&tools).err().unwrap().code, "E_TRUST");
    assert_eq!(
        store.list().unwrap().retained_roots,
        1,
        "failure preserves retained roots"
    );
}
