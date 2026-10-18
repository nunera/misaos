//! Binding of one selected export to the retained root it may run from.
//!
//! The plan is only a claim. Everything it names is re-derived from the
//! caller-owned store: the retained import receipt (found by the plan's declared
//! compose-receipt digest, never by position), its signed local-admission
//! evidence chain, the OCI graph, and the sealed tree. A forged root digest,
//! receipt digest, layout path, lock digest or edited rootfs fails here with a
//! typed error. This is local integrity only; publisher authentication is the
//! separate `publisher` gate.
use crate::{Error, Result, plan::Selection, tree};
use misa_image::{
    model::{self, LockedImage},
    store::{ImportReceipt, Toolchain},
    trust, verify,
};
use rustix::process::{geteuid, getuid};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const METADATA_LIMIT: u64 = 8 * 1024 * 1024;

/// A root that is intact and locally admitted, NOT yet publisher-authenticated.
#[derive(Clone, Debug)]
pub struct Binding {
    pub store: PathBuf,
    pub rootfs: PathBuf,
    pub receipt: ImportReceipt,
    pub receipt_digest: String,
    pub locked: LockedImage,
    pub platform: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Materialization {
    manifest_digest: String,
    tree_digest: String,
    #[serde(with = "misa_image::model::decimal")]
    materialized_bytes: u64,
    #[serde(with = "misa_image::model::decimal")]
    tree_entries: u64,
    toolchain: Toolchain,
}

fn state(field: &str, message: &str) -> Error {
    Error::new("E_STATE", field, message)
}

fn io(field: &str, error: impl std::fmt::Display) -> Error {
    Error::new("E_IO", field, format!("{field}: {error}"))
}

fn private_dir(path: &Path, uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io("store.directory", e))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(Error::new(
            "E_PATH_OWNER",
            "store.directory",
            "store directories must be caller-owned real directories with mode 0700",
        ));
    }
    Ok(())
}

/// Absolute, symlink-free, caller-owned private store path; never created here.
pub fn canonical_store(path: &Path) -> Result<PathBuf> {
    let uid = geteuid().as_raw();
    if uid == 0 || getuid().as_raw() != uid {
        return Err(Error::new(
            "E_PATH_OWNER",
            "store",
            "use an ordinary unprivileged caller; root and set-id callers are refused",
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| io("store.cwd", e))?
            .join(path)
    };
    let mut lexical = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => lexical.push(name),
            _ => {
                return Err(Error::new(
                    "E_PATH_OWNER",
                    "store.path",
                    "use a normalized store path without parent traversal",
                ));
            }
        }
        let metadata = fs::symlink_metadata(&lexical).map_err(|e| io("store.path", e))?;
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
    if lexical == Path::new("/") {
        return Err(Error::new(
            "E_PATH_OWNER",
            "store",
            "the filesystem root is not a caller-owned store",
        ));
    }
    private_dir(&lexical, uid)?;
    Ok(lexical)
}

fn read_regular(path: &Path, limit: u64, field: &str) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|e| io(field, e))?;
    if !file.metadata().map_err(|e| io(field, e))?.is_file() {
        return Err(state(field, "expected a regular retained metadata file"));
    }
    let mut bytes = Vec::new();
    Read::take(&file, limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io(field, e))?;
    if bytes.len() as u64 > limit {
        return Err(state(field, "retained metadata exceeds its bounded size"));
    }
    Ok(bytes)
}

fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|_| state("metadata", "cannot canonicalize retained metadata"))
}

fn receipt_id(receipt: &ImportReceipt) -> Result<String> {
    Ok(format!(
        "{}-{:x}-{}",
        model::digest_hex(&receipt.lock_digest)?,
        Sha256::digest(receipt.name.as_bytes()),
        model::digest_hex(&receipt.approval_digest)?
    ))
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| state("store.path", "store paths must be UTF-8"))
}

/// Locate, verify and bind the retained root for `selection`. Cheap identity
/// checks run first; OCI and tree hashing run last.
pub fn bind(store: &Path, selection: &Selection) -> Result<Binding> {
    let store = canonical_store(store)?;
    let uid = geteuid().as_raw();
    for relative in ["oci", "materialized", "receipts"] {
        private_dir(&store.join(relative), uid)?;
    }
    let root = &selection.root;
    let oci_layout = store.join("oci");
    if root.layout != path_str(&oci_layout)? {
        return Err(Error::new(
            "E_LOCK",
            "roots.sealedPath.layout",
            "the plan's sealed OCI layout is not this store's retained layout",
        ));
    }
    let manifest_hex = model::digest_hex(&root.digest)?.to_owned();

    let name_tag = format!("{:x}", Sha256::digest(root.source_lock_key.as_bytes()));
    let mut directories = Vec::new();
    for entry in fs::read_dir(store.join("receipts")).map_err(|e| io("receipts", e))? {
        let entry = entry.map_err(|e| io("receipts", e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| state("receipts", "non-UTF8 receipt directory name"))?;
        let parts: Vec<&str> = name.split('-').collect();
        if parts.len() != 3 {
            return Err(state("receipts", "malformed receipt directory name"));
        }
        if parts[1] == name_tag {
            directories.push((name, entry.path()));
        }
    }
    directories.sort();

    let mut found = None;
    for (name, directory) in directories {
        private_dir(&directory, uid)?;
        let receipt: ImportReceipt = model::parse_record(
            &read_regular(&directory.join("receipt.json"), METADATA_LIMIT, "receipt")?,
            "receipt",
        )?;
        if receipt_id(&receipt)? != name {
            return Err(state(
                "receipt",
                "receipt location disagrees with its admission identity",
            ));
        }
        let digest = misa_plan::hash_bytes(&canonical(&receipt)?);
        if receipt.manifest_digest == root.digest && digest == root.compose_receipt_digest {
            found = Some((directory, receipt, digest));
            break;
        }
    }
    let (directory, receipt, receipt_digest) = found.ok_or_else(|| {
        Error::new(
            "E_LOCK",
            "roots.composeReceiptDigest",
            "no retained receipt matches the plan's declared stratum, manifest and receipt digest",
        )
    })?;

    let authorized = trust::verify_approval(
        model::parse_lock(&read_regular(
            &directory.join("lock.json"),
            METADATA_LIMIT,
            "lock",
        )?)?,
        trust::parse_approval(&read_regular(
            &directory.join("approval.json"),
            METADATA_LIMIT,
            "approval",
        )?)?,
        trust::parse_public_key(&read_regular(
            &directory.join("public-key.json"),
            METADATA_LIMIT,
            "publicKey",
        )?)?,
    )?;
    let locked = authorized
        .lock()
        .strata
        .get(&receipt.name)
        .ok_or_else(|| state("receipt.name", "receipt stratum is not in its signed lock"))?
        .clone();
    let platform = authorized.lock().target_platform.clone();
    let rootfs = store
        .join("materialized")
        .join(&manifest_hex)
        .join("rootfs");
    let mismatch = receipt.schema_version != "misa.import/v1"
        || receipt.qualification != "R1"
        || receipt.storage_mode != "retain-all"
        || receipt.seal_mode != "read-only-permissions"
        || receipt.name != root.source_lock_key
        || receipt.lock_digest != authorized.lock_digest()
        || receipt.approval_digest != misa_plan::hash_bytes(&canonical(authorized.approval())?)
        || receipt.key_id != authorized.approval().key_id
        || receipt.manifest_digest != locked.image.digest
        || receipt.root_path != path_str(&rootfs)?
        || receipt.oci_layout != path_str(&oci_layout)?;
    if mismatch {
        return Err(state(
            "receipt",
            "receipt disagrees with its signed admission or this store's canonical paths",
        ));
    }
    if selection.foreign_lock_digest != receipt.lock_digest {
        return Err(Error::new(
            "E_LOCK",
            "inputs.foreignLockDigest",
            "the plan's foreign lock digest differs from the retained admitted lock",
        ));
    }
    if platform != root.platform {
        return Err(Error::new(
            "E_ABI",
            "roots.platform",
            "the plan's root platform differs from the admitted lock platform",
        ));
    }
    if locked.libc_family != root.libc_family {
        return Err(Error::new(
            "E_ABI",
            "roots.libcFamily",
            "the plan's libc family differs from the admitted lock",
        ));
    }

    let materialized = store.join("materialized").join(&manifest_hex);
    private_dir(&materialized, uid)?;
    let materialization: Materialization = model::parse_record(
        &read_regular(
            &materialized.join("materialization.json"),
            METADATA_LIMIT,
            "materialization",
        )?,
        "materialization",
    )?;
    if materialization.manifest_digest != root.digest
        || materialization.tree_digest != receipt.tree_digest
        || materialization.toolchain != receipt.toolchain
    {
        return Err(state(
            "materialization",
            "materialization identity disagrees with the retained receipt",
        ));
    }

    verify::verify_layout(&oci_layout, &locked, &platform)?;
    let tree = tree::digest(&rootfs, &locked.limits)?;
    if tree.digest != materialization.tree_digest
        || tree.bytes != materialization.materialized_bytes
        || tree.entries != materialization.tree_entries
    {
        return Err(state(
            "materialized.tree",
            "the retained rootfs differs from its sealed tree digest",
        ));
    }
    let rootfs = fs::canonicalize(&rootfs).map_err(|e| io("rootfs", e))?;
    if rootfs
        != store
            .join("materialized")
            .join(&manifest_hex)
            .join("rootfs")
    {
        return Err(state(
            "rootfs",
            "the retained rootfs resolves outside its canonical store location",
        ));
    }
    Ok(Binding {
        store,
        rootfs,
        receipt,
        receipt_digest,
        locked,
        platform,
    })
}
