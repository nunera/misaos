//! Caller-owned retain-all storage. Permission sealing is not runtime isolation:
//! the owner can chmod these caches; consumers still need a read-only/nosuid/nodev view.
use crate::model::{self, Descriptor, Limits, LockedImage, decimal};
use crate::tools::{self, Tools};
use crate::trust::{self, AuthorizedLock};
use crate::verify;
use crate::{Error, Result};
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const METADATA_LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Toolchain {
    pub skopeo: String,
    pub umoci: String,
    pub bwrap: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportReceipt {
    pub schema_version: String,
    pub name: String,
    pub manifest_digest: String,
    pub lock_digest: String,
    pub approval_digest: String,
    pub key_id: String,
    pub qualification: String,
    pub storage_mode: String,
    pub tree_digest: String,
    pub root_path: String,
    pub oci_layout: String,
    #[serde(with = "decimal")]
    pub expanded_bytes: u64,
    #[serde(with = "decimal")]
    pub entries: u64,
    #[serde(with = "decimal")]
    pub stripped_modes: u64,
    pub toolchain: Toolchain,
    pub seal_mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreStatus {
    pub schema_version: String,
    pub storage_mode: String,
    #[serde(with = "decimal")]
    pub retained_roots: u64,
    #[serde(with = "decimal")]
    pub retained_manifests: u64,
    #[serde(with = "decimal")]
    pub retained_receipts: u64,
    #[serde(with = "decimal")]
    pub retained_blob_bytes: u64,
    #[serde(with = "decimal")]
    pub materialized_bytes: u64,
    #[serde(with = "decimal")]
    pub incomplete_stages: u64,
    pub receipts: Vec<ImportReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Materialization {
    manifest_digest: String,
    tree_digest: String,
    #[serde(with = "decimal")]
    materialized_bytes: u64,
    #[serde(with = "decimal")]
    tree_entries: u64,
    toolchain: Toolchain,
}

pub struct Store {
    path: PathBuf,
    // The process lock protects every operation, including readers. The mutex also
    // serializes multiple callers sharing this Store inside one process.
    _lock: File,
    gate: Mutex<()>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let uid = rustix::process::geteuid().as_raw();
        if uid == 0 || rustix::process::getuid().as_raw() != uid {
            return Err(Error::new(
                "E_PATH_OWNER",
                "store",
                "use an ordinary unprivileged caller; root and set-id callers are refused",
            ));
        }
        let path = prepare_store_path(path, uid)?;
        let lock_path = path.join("writer.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&lock_path)
            .map_err(|e| io_error("store.writer", e))?;
        owned_regular(&lock, "store.writer", uid)?;
        lock.try_lock_exclusive().map_err(|_| {
            Error::new(
                "E_STATE",
                "store.writer",
                "store already in use; retry after the current operation closes its store",
            )
        })?;
        for relative in [
            "oci",
            "oci/blobs",
            "oci/blobs/sha256",
            "materialized",
            "receipts",
            "staging",
        ] {
            private_dir(&path.join(relative), uid)?;
        }
        let marker = path.join("oci/oci-layout");
        if !exists(&marker)? {
            write_new(&marker, b"{\"imageLayoutVersion\":\"1.0.0\"}")?;
        }
        let marker_value: Value = read_json(&marker)?;
        if marker_value != json!({"imageLayoutVersion":"1.0.0"}) {
            return Err(state(
                "oci-layout",
                "invalid OCI layout marker; restore verified metadata offline",
            ));
        }
        let index = path.join("oci/index.json");
        if !exists(&index)? {
            write_new(&index, &canonical(&empty_index())?)?;
        }
        read_index(&index)?;
        sync_dir(&path)?;
        Ok(Self {
            path,
            _lock: lock,
            gate: Mutex::new(()),
        })
    }

    pub fn import(
        &self,
        authorized: &AuthorizedLock,
        name: &str,
        source_layout: &Path,
        tools: &Tools,
    ) -> Result<ImportReceipt> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| state("store", "operation lock poisoned; reopen the store"))?;
        self.validate_structure()?;
        let locked = authorized.lock().strata.get(name).ok_or_else(|| {
            Error::new(
                "E_LOCK",
                "name",
                "stratum absent from the authorized lock; select an admitted stratum",
            )
        })?;
        let stage = tempfile::Builder::new()
            .prefix("import-")
            .tempdir_in(self.path.join("staging"))
            .map_err(|e| io_error("staging", e))?
            .keep();
        // Intentionally retain failed staging for offline inspection. Nothing from
        // it becomes an OCI index entry until all verification and sealing succeeds.
        let snapshot = stage.join("image");
        copy_snapshot(source_layout, &snapshot, locked)?;
        let verified =
            verify::verify_layout(&snapshot, locked, &authorized.lock().target_platform)?;
        let manifest_hex = model::digest_hex(&verified.manifest.digest)?;
        let materialized = self.path.join("materialized").join(manifest_hex);
        let root = materialized.join("rootfs");
        let materialization: Materialization;
        if exists(&materialized)? {
            require_private_dir(&materialized, rustix::process::geteuid().as_raw())?;
            materialization = read_json(&materialized.join("materialization.json"))?;
            verify_materialization(&materialization, &root, locked)?;
        } else {
            // Only this private, already verified snapshot gets an extraction tag.
            replace_json(
                &snapshot.join("index.json"),
                &single_index(&verified.manifest, "locked"),
            )?;
            let output = stage.join("output");
            private_dir(&output, rustix::process::geteuid().as_raw())?;
            unpack(&snapshot, &output, tools, &locked.limits)?;
            let extracted = output.join("bundle/rootfs");
            let candidate = stage.join("materialization");
            private_dir(&candidate, rustix::process::geteuid().as_raw())?;
            // Moving a directory changes ".." and requires directory write access.
            // Put rootfs in its final private parent before removing write bits;
            // publication then moves only the still-writable outer directory.
            rename_new(&extracted, &candidate.join("rootfs"))?;
            let tree = inspect_tree(&candidate.join("rootfs"), &locked.limits, true)?;
            materialization = Materialization {
                manifest_digest: verified.manifest.digest.clone(),
                tree_digest: tree.digest,
                materialized_bytes: tree.bytes,
                tree_entries: tree.entries,
                toolchain: toolchain(tools)?,
            };
            // A materialization is published as one complete directory, never an
            // incrementally filled public rootfs. renameat2 must not replace it.
            write_new(
                &candidate.join("materialization.json"),
                &canonical(&materialization)?,
            )?;
            sync_dir(&candidate)?;
            rename_new(&candidate, &materialized)?;
            sync_dir(&self.path.join("materialized"))?;
        }
        // All retained source blobs remain byte-for-byte OCI artifacts. Existing
        // names are independently hashed, never overwritten even after corruption.
        for descriptor in &verified.descriptors {
            let hex = model::digest_hex(&descriptor.digest)?;
            let destination = self.path.join("oci/blobs/sha256").join(hex);
            if exists(&destination)? {
                check_blob(&destination, descriptor, &locked.limits)?;
            } else {
                let source = snapshot.join("blobs/sha256").join(hex);
                fs::set_permissions(&source, fs::Permissions::from_mode(0o444))
                    .map_err(|e| io_error("blob.mode", e))?;
                open_regular(&source)?
                    .sync_all()
                    .map_err(|e| io_error("blob.fsync", e))?;
                fs::hard_link(&source, &destination).map_err(|e| io_error("blob.publish", e))?;
            }
        }
        sync_dir(&self.path.join("oci/blobs/sha256"))?;
        let approval_bytes = canonical(authorized.approval())?;
        let approval_digest = misa_plan::hash_bytes(&approval_bytes);
        let receipt = ImportReceipt {
            schema_version: "misa.import/v1".into(),
            name: name.into(),
            manifest_digest: verified.manifest.digest.clone(),
            lock_digest: authorized.lock_digest().into(),
            approval_digest,
            key_id: authorized.approval().key_id.clone(),
            qualification: "R1".into(),
            storage_mode: "retain-all".into(),
            tree_digest: materialization.tree_digest.clone(),
            root_path: path_string(&root)?,
            oci_layout: path_string(&self.path.join("oci"))?,
            expanded_bytes: verified.expanded_bytes,
            entries: verified.entries,
            stripped_modes: verified.stripped_modes,
            toolchain: materialization.toolchain,
            seal_mode: "read-only-permissions".into(),
        };
        let evidence = self.path.join("receipts").join(receipt_id(&receipt)?);
        if exists(&evidence)? {
            require_private_dir(&evidence, rustix::process::geteuid().as_raw())?;
            let retained: ImportReceipt = read_json(&evidence.join("receipt.json"))?;
            if retained != receipt {
                return Err(state(
                    "receipt",
                    "existing receipt differs; preserve it and inspect corruption offline",
                ));
            }
            check_bytes(
                &evidence.join("lock.json"),
                &model::canonical_lock(authorized.lock())?,
            )?;
            check_bytes(&evidence.join("approval.json"), &approval_bytes)?;
            check_bytes(
                &evidence.join("public-key.json"),
                &canonical(authorized.public_key())?,
            )?;
        } else {
            let candidate = stage.join("evidence");
            private_dir(&candidate, rustix::process::geteuid().as_raw())?;
            write_new(&candidate.join("receipt.json"), &canonical(&receipt)?)?;
            write_new(
                &candidate.join("lock.json"),
                &model::canonical_lock(authorized.lock())?,
            )?;
            write_new(&candidate.join("approval.json"), &approval_bytes)?;
            write_new(
                &candidate.join("public-key.json"),
                &canonical(authorized.public_key())?,
            )?;
            sync_dir(&candidate)?;
            rename_new(&candidate, &evidence)?;
            sync_dir(&self.path.join("receipts"))?;
        }
        let index_path = self.path.join("oci/index.json");
        let mut index = read_index(&index_path)?;
        let manifests = index["manifests"]
            .as_array_mut()
            .expect("validated index array");
        if !manifests
            .iter()
            .any(|d| d["digest"].as_str() == Some(&receipt.manifest_digest))
        {
            manifests.push(wire_descriptor(&verified.manifest, manifest_hex));
            manifests.sort_by(|a, b| a["digest"].as_str().cmp(&b["digest"].as_str()));
            replace_json(&index_path, &index)?;
        }
        // Removing only this successful invocation's private work area is not GC;
        // retained roots, receipts and CAS objects are never collected or repaired.
        fs::remove_dir_all(&stage).map_err(|e| io_error("staging.cleanup", e))?;
        sync_dir(&self.path.join("staging"))?;
        Ok(receipt)
    }

    pub fn list(&self) -> Result<StoreStatus> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| state("store", "operation lock poisoned; reopen the store"))?;
        self.status()
    }

    /// Offline integrity check, not publisher authentication or runtime isolation.
    /// No network, tool execution, mutation, repair, or garbage collection occurs.
    pub fn doctor(&self, _tools: &Tools) -> Result<StoreStatus> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| state("store", "operation lock poisoned; reopen the store"))?;
        let status = self.status()?;
        let mut checked_roots = BTreeSet::new();
        let mut checked_manifests = BTreeSet::new();
        for receipt in &status.receipts {
            let evidence = self.path.join("receipts").join(receipt_id(receipt)?);
            let lock =
                model::parse_lock(&read_bounded(&evidence.join("lock.json"), METADATA_LIMIT)?)?;
            let approval = trust::parse_approval(&read_bounded(
                &evidence.join("approval.json"),
                METADATA_LIMIT,
            )?)?;
            let key = trust::parse_public_key(&read_bounded(
                &evidence.join("public-key.json"),
                METADATA_LIMIT,
            )?)?;
            let authorized = trust::verify_approval(lock, approval, key)?;
            let locked = authorized.lock().strata.get(&receipt.name).ok_or_else(|| {
                state(
                    "receipt.name",
                    "receipt stratum is not in its signed lock; inspect evidence offline",
                )
            })?;
            let verified = verify::verify_layout(
                &self.path.join("oci"),
                locked,
                &authorized.lock().target_platform,
            )?;
            let root_dir = self
                .path
                .join("materialized")
                .join(model::digest_hex(&locked.image.digest)?);
            let root = root_dir.join("rootfs");
            require_private_dir(&root_dir, rustix::process::geteuid().as_raw())?;
            let materialization: Materialization =
                read_json(&root_dir.join("materialization.json"))?;
            // Different signed policies for one manifest are each checked above;
            // the cache tree is likewise checked under each receipt's bounds.
            verify_materialization(&materialization, &root, locked)?;
            if receipt.schema_version != "misa.import/v1"
                || receipt.qualification != "R1"
                || receipt.storage_mode != "retain-all"
                || receipt.seal_mode != "read-only-permissions"
                || receipt.lock_digest != authorized.lock_digest()
                || receipt.approval_digest
                    != misa_plan::hash_bytes(&canonical(authorized.approval())?)
                || receipt.key_id != authorized.approval().key_id
                || receipt.manifest_digest != locked.image.digest
                || receipt.tree_digest != materialization.tree_digest
                || receipt.toolchain != materialization.toolchain
                || receipt.root_path != path_string(&root)?
                || receipt.oci_layout != path_string(&self.path.join("oci"))?
                || receipt.expanded_bytes != verified.expanded_bytes
                || receipt.entries != verified.entries
                || receipt.stripped_modes != verified.stripped_modes
            {
                return Err(state(
                    "receipt",
                    "receipt disagrees with signed admission or verified artifacts; inspect retained evidence offline",
                ));
            }
            checked_roots.insert(locked.image.digest.clone());
            checked_manifests.insert(locked.image.digest.clone());
        }
        let index = read_index(&self.path.join("oci/index.json"))?;
        for descriptor in index["manifests"].as_array().expect("validated array") {
            if !checked_manifests.contains(descriptor["digest"].as_str().unwrap_or("")) {
                return Err(state(
                    "oci.index",
                    "indexed manifest has no verified local admission receipt; inspect incomplete publication offline",
                ));
            }
        }
        // Even unreferenced CAS objects have content-addressed names. A crash may
        // retain one, but never excuses corrupted bytes under a digest filename.
        for entry in sorted_children(&self.path.join("oci/blobs/sha256"))? {
            let name = entry
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| state("blob", "non-UTF8 CAS name"))?;
            let digest = format!("sha256:{name}");
            model::digest_hex(&digest)?;
            let mut file = open_regular(&entry)?;
            let size = file.metadata().map_err(|e| io_error("blob", e))?.len();
            let actual = hash_reader(
                &mut file,
                size,
                Some(Instant::now() + Duration::from_secs(Limits::default().timeout_seconds)),
            )?;
            if actual != digest {
                return Err(state(
                    "blob.digest",
                    "retained blob digest mismatch; restore verified bytes offline, never overwrite automatically",
                ));
            }
        }
        if checked_roots.len() as u64 != status.retained_roots {
            return Err(state(
                "materialized",
                "retained root lacks complete admission evidence; inspect interrupted publication offline",
            ));
        }
        Ok(status)
    }

    fn validate_structure(&self) -> Result<()> {
        let uid = rustix::process::geteuid().as_raw();
        for relative in [
            "",
            "oci",
            "oci/blobs",
            "oci/blobs/sha256",
            "materialized",
            "receipts",
            "staging",
        ] {
            require_private_dir(&self.path.join(relative), uid)?;
        }
        let marker: Value = read_json(&self.path.join("oci/oci-layout"))?;
        if marker != json!({"imageLayoutVersion":"1.0.0"}) {
            return Err(state(
                "oci-layout",
                "layout marker changed; inspect retained state offline",
            ));
        }
        Ok(())
    }

    fn status(&self) -> Result<StoreStatus> {
        self.validate_structure()?;
        let mut receipts = Vec::new();
        for directory in sorted_children(&self.path.join("receipts"))? {
            require_private_dir(&directory, rustix::process::geteuid().as_raw())?;
            let receipt: ImportReceipt = read_json(&directory.join("receipt.json"))?;
            if directory.file_name().and_then(|s| s.to_str())
                != Some(receipt_id(&receipt)?.as_str())
            {
                return Err(state(
                    "receipt",
                    "receipt location disagrees with its admission identity",
                ));
            }
            receipts.push(receipt);
        }
        let roots = sorted_children(&self.path.join("materialized"))?;
        let mut materialized_bytes = 0u64;
        for root in &roots {
            require_private_dir(root, rustix::process::geteuid().as_raw())?;
            let name = root
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| state("materialized", "invalid root name"))?;
            model::digest_hex(&format!("sha256:{name}"))?;
            materialized_bytes = add(materialized_bytes, directory_bytes(&root.join("rootfs"))?)?;
        }
        let index = read_index(&self.path.join("oci/index.json"))?;
        let mut retained_blob_bytes = 0u64;
        for blob in sorted_children(&self.path.join("oci/blobs/sha256"))? {
            retained_blob_bytes = add(
                retained_blob_bytes,
                open_regular(&blob)?
                    .metadata()
                    .map_err(|e| io_error("blob", e))?
                    .len(),
            )?;
        }
        Ok(StoreStatus {
            schema_version: "misa.store/v1".into(),
            storage_mode: "retain-all".into(),
            retained_roots: roots.len() as u64,
            retained_manifests: index["manifests"]
                .as_array()
                .expect("validated array")
                .len() as u64,
            retained_receipts: receipts.len() as u64,
            retained_blob_bytes,
            materialized_bytes,
            incomplete_stages: sorted_children(&self.path.join("staging"))?.len() as u64,
            receipts,
        })
    }
}

fn copy_snapshot(source: &Path, destination: &Path, locked: &LockedImage) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    for relative in ["", "blobs", "blobs/sha256"] {
        private_dir(&destination.join(relative), uid)?;
    }
    let source_fd = open_directory(source)?;
    let deadline = Instant::now() + Duration::from_secs(locked.limits.timeout_seconds);
    for name in ["oci-layout", "index.json"] {
        let file = confined_file(&source_fd, Path::new(name))?;
        let bytes = read_handle(file, METADATA_LIMIT, name)?;
        write_new(&destination.join(name), &bytes)?;
    }
    let mut copied = BTreeSet::new();
    let mut total = 0;
    // Metadata (index, manifest, config) plus bounded compressed layer storage.
    // This conservative cap also bounds snapshot disk consumption before tar scan.
    let snapshot_limit = locked
        .limits
        .max_expanded_bytes
        .saturating_add(locked.limits.max_blob_bytes.saturating_mul(3));
    let mut copy = |descriptor: &Descriptor| -> Result<()> {
        let hex = model::digest_hex(&descriptor.digest)?;
        if !copied.insert(descriptor.digest.clone()) {
            return Ok(());
        }
        if descriptor.size > locked.limits.max_blob_bytes {
            return Err(state(
                "snapshot",
                "blob exceeds signed policy; resolve with an appropriate bounded policy",
            ));
        }
        total = add(total, descriptor.size)?;
        if total > snapshot_limit {
            return Err(state(
                "snapshot",
                "aggregate snapshot exceeds expanded-plus-metadata budget",
            ));
        }
        let relative = PathBuf::from("blobs/sha256").join(hex);
        let mut input = confined_file(&source_fd, &relative)?;
        if input
            .metadata()
            .map_err(|e| io_error("snapshot.blob", e))?
            .len()
            != descriptor.size
        {
            return Err(state(
                "snapshot.blob",
                "source blob size differs from its descriptor; obtain the locked bytes",
            ));
        }
        let mut output = create_file(&destination.join(relative))?;
        let mut hasher = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            check_deadline(deadline)?;
            let n = input
                .read(&mut buffer)
                .map_err(|e| io_error("snapshot.read", e))?;
            if n == 0 {
                break;
            }
            count = add(count, n as u64)?;
            if count > descriptor.size {
                return Err(state(
                    "snapshot.blob",
                    "source blob grew during copy; obtain a stable locked source",
                ));
            }
            hasher.update(&buffer[..n]);
            output
                .write_all(&buffer[..n])
                .map_err(|e| io_error("snapshot.write", e))?;
        }
        if count != descriptor.size
            || format!("sha256:{:x}", hasher.finalize()) != descriptor.digest
        {
            return Err(state(
                "snapshot.blob",
                "source descriptor digest/size mismatch; obtain the locked bytes",
            ));
        }
        output
            .sync_all()
            .map_err(|e| io_error("snapshot.fsync", e))?;
        Ok(())
    };
    copy(&locked.image)?;
    if let Some(index) = &locked.source_index {
        copy(index)?;
    }
    let manifest_path = destination
        .join("blobs/sha256")
        .join(model::digest_hex(&locked.image.digest)?);
    let manifest: Value =
        model::parse_record(&read_bounded(&manifest_path, METADATA_LIMIT)?, "manifest")?;
    copy(&parse_wire_descriptor(&manifest["config"])?)?;
    let layers = manifest["layers"]
        .as_array()
        .ok_or_else(|| state("manifest.layers", "expected layer descriptor array"))?;
    if layers.len() as u64 > locked.limits.max_entries {
        return Err(state(
            "manifest.layers",
            "layer count exceeds signed entry limit",
        ));
    }
    for layer in layers {
        copy(&parse_wire_descriptor(layer)?)?;
    }
    sync_dir(&destination.join("blobs/sha256"))?;
    sync_dir(destination)
}

fn unpack(snapshot: &Path, output: &Path, tools: &Tools, limits: &Limits) -> Result<()> {
    // Trusted tool paths must be immutable Nix store paths; the sandbox sees no
    // caller home, host /etc, host network, or imported executable entrypoint.
    for path in [&tools.umoci, &tools.bwrap] {
        if !path.is_absolute() || !path.starts_with("/nix/store") {
            return Err(Error::new(
                "E_CAPABILITY",
                "toolchain",
                "sandboxed import requires caller-trusted absolute /nix/store tool paths",
            ));
        }
    }
    let mut command = Command::new(&tools.bwrap);
    command
        .args([
            "--die-with-parent",
            "--unshare-all",
            "--new-session",
            "--clearenv",
        ])
        .arg("--uid")
        .arg(rustix::process::geteuid().as_raw().to_string())
        .arg("--gid")
        .arg(rustix::process::getegid().as_raw().to_string())
        .args([
            "--ro-bind",
            "/nix/store",
            "/nix/store",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(snapshot)
        .arg("/image")
        .arg("--bind")
        .arg(output)
        .arg("/output")
        .args(["--chdir", "/", "--"])
        .arg(&tools.umoci)
        .args([
            "unpack",
            "--rootless",
            "--image",
            "/image:locked",
            "/output/bundle",
        ]);
    tools::run_capture(
        &mut command,
        Duration::from_secs(limits.timeout_seconds),
        64 * 1024,
    )?;
    Ok(())
}

struct Tree {
    digest: String,
    bytes: u64,
    entries: u64,
}

fn inspect_tree(root: &Path, limits: &Limits, seal: bool) -> Result<Tree> {
    let root_fd = open_directory(root)?;
    let uid = rustix::process::geteuid().as_raw();
    let deadline = Instant::now() + Duration::from_secs(limits.timeout_seconds);
    let mut hash = Sha256::new();
    frame(&mut hash, b"misa.derived-tree/v1");
    let mut bytes = 0u64;
    let mut entries = 0u64;
    // Postorder chmod is essential: removing directory write bits early could
    // obstruct processing descendants. Digest order remains deterministic.
    let mut directories = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .follow_root_links(false)
        .sort_by_file_name()
    {
        check_deadline(deadline)?;
        let entry = entry.map_err(|_| {
            state(
                "tree",
                "cannot traverse retained tree without following links",
            )
        })?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| state("tree", "tree path escaped its root"))?;
        if relative.as_os_str().as_bytes().len() as u64 > limits.max_path_bytes
            || entry.depth() > 64
        {
            return Err(state(
                "tree.path",
                "materialized path exceeds signed length/depth limits",
            ));
        }
        entries = add(entries, 1)?;
        // The root directory is not necessarily represented by a tar entry.
        if entries > limits.max_entries.saturating_add(1) {
            return Err(state(
                "tree.entries",
                "materialized entry count exceeds signed policy",
            ));
        }
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|e| io_error("tree.metadata", e))?;
        if metadata.uid() != uid {
            return Err(Error::new(
                "E_PATH_OWNER",
                "tree.uid",
                "rootless materialization must map every node to the importing caller",
            ));
        }
        frame(&mut hash, relative.as_os_str().as_bytes());
        frame_rootless_metadata(&mut hash, entry.path())?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(entry.path()).map_err(|e| io_error("tree.symlink", e))?;
            frame(&mut hash, b"symlink");
            frame(&mut hash, &(metadata.mode() & 0o7777).to_be_bytes());
            frame(&mut hash, target.as_os_str().as_bytes());
        } else if metadata.is_file() || metadata.is_dir() {
            let path = if relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                relative
            };
            let file = confined_node(&root_fd, path, metadata.is_dir())?;
            let current = file.metadata().map_err(|e| io_error("tree.metadata", e))?;
            let mode = current.mode() & 0o1777 & !0o222;
            if !seal && current.mode() & 0o6222 != 0 {
                return Err(state(
                    "tree.mode",
                    "retained tree gained writable or privileged mode bits; inspect offline",
                ));
            }
            if metadata.is_dir() {
                frame(&mut hash, b"directory");
                frame(&mut hash, &mode.to_be_bytes());
                frame(&mut hash, b"");
                if seal {
                    directories.push((entry.path().to_path_buf(), mode));
                }
            } else {
                if current.len() > limits.max_file_bytes {
                    return Err(state(
                        "tree.file",
                        "materialized file exceeds signed byte limit",
                    ));
                }
                bytes = add(bytes, current.len())?;
                if bytes > limits.max_expanded_bytes {
                    return Err(state(
                        "tree.bytes",
                        "materialized bytes exceed signed expansion budget",
                    ));
                }
                let digest = hash_reader(&mut &file, current.len(), Some(deadline))?;
                frame(&mut hash, b"file");
                frame(&mut hash, &mode.to_be_bytes());
                frame(&mut hash, digest.as_bytes());
                if seal {
                    file.set_permissions(fs::Permissions::from_mode(mode))
                        .map_err(|e| io_error("tree.seal", e))?;
                    file.sync_all().map_err(|e| io_error("tree.fsync", e))?;
                }
            }
        } else {
            return Err(state(
                "tree.type",
                "materialization contains a device, fifo, socket or unsupported type",
            ));
        }
    }
    for (directory, mode) in directories.into_iter().rev() {
        let file = open_directory(&directory)?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| io_error("tree.seal", e))?;
        file.sync_all().map_err(|e| io_error("tree.fsync", e))?;
    }
    Ok(Tree {
        digest: format!("sha256:{:x}", hash.finalize()),
        bytes,
        entries,
    })
}

fn verify_materialization(
    record: &Materialization,
    root: &Path,
    locked: &LockedImage,
) -> Result<()> {
    if record.manifest_digest != locked.image.digest {
        return Err(state(
            "materialized.manifest",
            "materialization identity disagrees with signed OCI manifest",
        ));
    }
    let tree = inspect_tree(root, &locked.limits, false)?;
    if tree.digest != record.tree_digest
        || tree.bytes != record.materialized_bytes
        || tree.entries != record.tree_entries
    {
        return Err(state(
            "materialized.tree",
            "derived tree digest or accounting mismatch; preserve evidence and restore the cache offline",
        ));
    }
    Ok(())
}

fn frame_rootless_metadata(hash: &mut Sha256, path: &Path) -> Result<()> {
    // umoci v0.6.0 creates this inert UID/GID bookkeeping for non-root tar
    // owners. All *archive* xattrs are rejected before extraction, so imported
    // bytes cannot impersonate it. Never interpret it as runtime authority.
    const NAME: &[u8] = b"user.rootlesscontainers\0";
    let mut names = [0u8; 64];
    let count = rustix::fs::llistxattr(path, &mut names[..]).map_err(|_| {
        state(
            "tree.xattrs",
            "cannot enumerate bounded rootless metadata; unexpected xattrs are refused",
        )
    })?;
    if count == 0 {
        frame(hash, b"");
        frame(hash, b"");
    } else {
        if &names[..count] != NAME {
            return Err(state(
                "tree.xattrs",
                "only umoci-generated user.rootlesscontainers bookkeeping is allowed",
            ));
        }
        let mut value = [0u8; 64];
        let count = rustix::fs::lgetxattr(path, "user.rootlesscontainers", &mut value[..])
            .map_err(|_| {
                state(
                    "tree.xattrs",
                    "rootless ownership metadata exceeds its bounded representation",
                )
            })?;
        if count == 0 {
            return Err(state(
                "tree.xattrs",
                "empty rootless ownership metadata is invalid",
            ));
        }
        frame(hash, &NAME[..NAME.len() - 1]);
        frame(hash, &value[..count]);
    }
    Ok(())
}

fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn prepare_store_path(path: &Path, uid: u32) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| io_error("store.cwd", e))?
            .join(path)
    };
    if absolute == Path::new("/") {
        return Err(state(
            "store",
            "filesystem root is not a caller-owned store",
        ));
    }
    let mut current = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => current.push(name),
            _ => {
                return Err(Error::new(
                    "E_PATH_OWNER",
                    "store.path",
                    "use a normalized path without parent traversal",
                ));
            }
        }
        if !exists(&current)? {
            DirBuilder::new()
                .mode(0o700)
                .create(&current)
                .map_err(|e| io_error("store.mkdir", e))?;
            sync_dir(current.parent().expect("non-root path"))?;
        }
        let metadata = fs::symlink_metadata(&current).map_err(|e| io_error("store.path", e))?;
        let trusted_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != uid && metadata.uid() != 0)
            || (metadata.mode() & 0o022 != 0 && !trusted_sticky)
        {
            return Err(Error::new(
                "E_PATH_OWNER",
                "store.path",
                "store ancestors must be real trusted directories, not symlinks or writable by other users",
            ));
        }
    }
    require_private_dir(&current, uid)?;
    Ok(current)
}

fn private_dir(path: &Path, uid: u32) -> Result<()> {
    if !exists(path)? {
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|e| io_error("store.mkdir", e))?;
        sync_dir(
            path.parent()
                .ok_or_else(|| state("store.path", "directory lacks parent"))?,
        )?;
    }
    require_private_dir(path, uid)
}

fn require_private_dir(path: &Path, uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io_error("store.directory", e))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(Error::new(
            "E_PATH_OWNER",
            "store.directory",
            "store directories must be caller-owned real directories with mode 0700; choose a private store",
        ));
    }
    Ok(())
}

fn owned_regular(file: &File, field: &str, uid: u32) -> Result<()> {
    let metadata = file.metadata().map_err(|e| io_error(field, e))?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(Error::new(
            "E_PATH_OWNER",
            field,
            "expected a private caller-owned regular lock file with one link",
        ));
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<File> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io_error("directory.open", e))?;
    Ok(File::from(fd))
}

fn confined_node(root: &File, relative: &Path, directory: bool) -> Result<File> {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    let fd = rustix::fs::openat2(
        root,
        relative,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|e| io_error("confined.open", e))?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|e| io_error("confined.metadata", e))?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(state(
            "confined.type",
            "expected ordinary file/directory, not a special file",
        ));
    }
    Ok(file)
}

fn confined_file(root: &File, relative: &Path) -> Result<File> {
    confined_node(root, relative, false)
}

fn open_regular(path: &Path) -> Result<File> {
    let parent = open_directory(
        path.parent()
            .ok_or_else(|| state("file", "file path lacks parent"))?,
    )?;
    confined_file(
        &parent,
        Path::new(
            path.file_name()
                .ok_or_else(|| state("file", "file path lacks name"))?,
        ),
    )
}

fn create_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|e| io_error("file.create", e))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_file(path)?;
    file.write_all(bytes)
        .map_err(|e| io_error("file.write", e))?;
    file.set_permissions(fs::Permissions::from_mode(0o444))
        .map_err(|e| io_error("file.mode", e))?;
    file.sync_all().map_err(|e| io_error("file.fsync", e))?;
    sync_dir(
        path.parent()
            .ok_or_else(|| state("file", "file lacks parent"))?,
    )
}

fn replace_json(path: &Path, value: &Value) -> Result<()> {
    let bytes = canonical(value)?;
    if bytes.len() > misa_plan::MAX_INPUT_BYTES {
        return Err(state(
            "index",
            "retained OCI index exceeds the strict metadata bound; preserve this store and use a separate caller-owned store",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| state("index", "index lacks parent"))?;
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(|e| io_error("index.stage", e))?;
    file.write_all(&bytes)
        .map_err(|e| io_error("index.write", e))?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))
        .map_err(|e| io_error("index.mode", e))?;
    file.as_file()
        .sync_all()
        .map_err(|e| io_error("index.fsync", e))?;
    file.persist(path)
        .map_err(|e| io_error("index.publish", e.error))?;
    sync_dir(parent)
}

fn rename_new(source: &Path, destination: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|e| io_error("store.publish", e))?;
    sync_dir(
        source
            .parent()
            .ok_or_else(|| state("rename", "source lacks parent"))?,
    )?;
    sync_dir(
        destination
            .parent()
            .ok_or_else(|| state("rename", "destination lacks parent"))?,
    )
}

fn sync_dir(path: &Path) -> Result<()> {
    open_directory(path)?
        .sync_all()
        .map_err(|e| io_error("directory.fsync", e))
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error("path", e)),
    }
}
fn read_handle(mut file: File, limit: u64, field: &str) -> Result<Vec<u8>> {
    if !file.metadata().map_err(|e| io_error(field, e))?.is_file() {
        return Err(state(field, "expected regular metadata file"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(field, e))?;
    if bytes.len() as u64 > limit {
        return Err(state(field, "metadata exceeds bounded input size"));
    }
    Ok(bytes)
}
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    read_handle(open_regular(path)?, limit, "metadata")
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    model::parse_record(&read_bounded(path, METADATA_LIMIT)?, "store.metadata")
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|_| state("metadata", "cannot canonicalize retained metadata"))
}
fn check_bytes(path: &Path, expected: &[u8]) -> Result<()> {
    if read_bounded(path, METADATA_LIMIT)? != expected {
        return Err(state(
            "evidence",
            "retained evidence differs; preserve it and inspect offline",
        ));
    }
    Ok(())
}
fn hash_reader(reader: &mut impl Read, expected: u64, deadline: Option<Instant>) -> Result<String> {
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if let Some(deadline) = deadline {
            check_deadline(deadline)?;
        }
        let n = reader
            .read(&mut buffer)
            .map_err(|e| io_error("digest.read", e))?;
        if n == 0 {
            break;
        }
        count = add(count, n as u64)?;
        if count > expected {
            return Err(state(
                "digest",
                "file grew while hashing; preserve evidence and retry with stable bytes",
            ));
        }
        hash.update(&buffer[..n]);
    }
    if count != expected {
        return Err(state("digest", "file size changed during hashing"));
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}
fn check_blob(path: &Path, descriptor: &Descriptor, limits: &Limits) -> Result<()> {
    let mut file = open_regular(path)?;
    if file.metadata().map_err(|e| io_error("blob", e))?.len() != descriptor.size
        || hash_reader(
            &mut file,
            descriptor.size,
            Some(Instant::now() + Duration::from_secs(limits.timeout_seconds)),
        )? != descriptor.digest
    {
        return Err(state(
            "blob.digest",
            "existing CAS content is corrupt; import never overwrites retained bytes",
        ));
    }
    Ok(())
}
fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() > deadline {
        return Err(Error::new(
            "E_BUILD",
            "deadline",
            "bounded import/storage operation timed out; inspect input or adjust signed policy",
        ));
    }
    Ok(())
}
fn sorted_children(path: &Path) -> Result<Vec<PathBuf>> {
    let mut children = fs::read_dir(path)
        .map_err(|e| io_error("directory.list", e))?
        .map(|entry| {
            entry
                .map(|e| e.path())
                .map_err(|e| io_error("directory.entry", e))
        })
        .collect::<Result<Vec<_>>>()?;
    children.sort();
    Ok(children)
}
fn directory_bytes(path: &Path) -> Result<u64> {
    let _root = open_directory(path)?;
    let mut bytes = 0;
    for entry in walkdir::WalkDir::new(path)
        .follow_links(false)
        .follow_root_links(false)
    {
        let entry =
            entry.map_err(|_| state("tree", "cannot account for retained materialization"))?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|e| io_error("tree", e))?;
        if metadata.is_file() {
            bytes = add(bytes, metadata.len())?;
        } else if !metadata.is_dir() && !metadata.file_type().is_symlink() {
            return Err(state("tree", "unsupported materialized node type"));
        }
    }
    Ok(bytes)
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| state("bytes", "retained accounting overflow"))
}
fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| state("path", "store and tool paths must be UTF-8 for receipts"))
}
fn toolchain(tools: &Tools) -> Result<Toolchain> {
    Ok(Toolchain {
        skopeo: path_string(&tools.skopeo)?,
        umoci: path_string(&tools.umoci)?,
        bwrap: path_string(&tools.bwrap)?,
    })
}
fn receipt_id(receipt: &ImportReceipt) -> Result<String> {
    Ok(format!(
        "{}-{:x}-{}",
        model::digest_hex(&receipt.lock_digest)?,
        Sha256::digest(receipt.name.as_bytes()),
        model::digest_hex(&receipt.approval_digest)?
    ))
}
fn empty_index() -> Value {
    json!({"schemaVersion":2,"mediaType":model::OCI_INDEX,"manifests":[]})
}
fn wire_descriptor(descriptor: &Descriptor, tag: &str) -> Value {
    json!({"mediaType":descriptor.media_type,"digest":descriptor.digest,"size":descriptor.size,"annotations":{"org.opencontainers.image.ref.name":tag}})
}
fn single_index(descriptor: &Descriptor, tag: &str) -> Value {
    json!({"schemaVersion":2,"mediaType":model::OCI_INDEX,"manifests":[wire_descriptor(descriptor, tag)]})
}
fn parse_wire_descriptor(value: &Value) -> Result<Descriptor> {
    let descriptor = Descriptor {
        media_type: value["mediaType"]
            .as_str()
            .ok_or_else(|| state("descriptor.mediaType", "missing OCI media type"))?
            .into(),
        digest: value["digest"]
            .as_str()
            .ok_or_else(|| state("descriptor.digest", "missing OCI digest"))?
            .into(),
        size: value["size"]
            .as_u64()
            .filter(|size| *size <= 9_007_199_254_740_991)
            .ok_or_else(|| state("descriptor.size", "expected safe integral OCI byte count"))?,
    };
    model::digest_hex(&descriptor.digest)?;
    Ok(descriptor)
}
fn read_index(path: &Path) -> Result<Value> {
    let index: Value = read_json(path)?;
    if index["schemaVersion"] != 2 || index["mediaType"] != model::OCI_INDEX {
        return Err(state(
            "oci.index",
            "retained OCI index schema/media type mismatch",
        ));
    }
    let manifests = index["manifests"]
        .as_array()
        .ok_or_else(|| state("oci.index", "missing manifest descriptors"))?;
    let mut seen = BTreeMap::new();
    for entry in manifests {
        let descriptor = parse_wire_descriptor(entry)?;
        if descriptor.media_type != model::OCI_MANIFEST
            || seen.insert(descriptor.digest, ()).is_some()
        {
            return Err(state(
                "oci.index",
                "retained index must contain unique OCI image manifests",
            ));
        }
    }
    Ok(index)
}
fn state(field: &str, message: &str) -> Error {
    Error::new("E_STATE", field, message)
}
fn io_error(field: &str, error: impl std::fmt::Display) -> Error {
    Error::new(
        "E_IO",
        field,
        format!(
            "filesystem operation failed ({error}); preserve retained state and inspect permissions/storage"
        ),
    )
}
