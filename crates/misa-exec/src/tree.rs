//! Re-derivation of the retained tree identity. The framing is byte-identical to
//! the importer's `misa.derived-tree/v1` (non-sealing mode): any divergence in
//! content, type, mode, xattr bookkeeping, or a write/set-id bit on any node
//! changes or refuses the digest, so a sealed root cannot be quietly edited.
use crate::{Error, Result};
use misa_image::model::Limits;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub struct TreeDigest {
    pub digest: String,
    pub bytes: u64,
    pub entries: u64,
}

fn state(field: &str, message: &str) -> Error {
    Error::new("E_STATE", field, message)
}

fn io(field: &str, error: impl std::fmt::Display) -> Error {
    Error::new("E_IO", field, format!("{field}: {error}"))
}

fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| state("tree", "retained accounting overflow"))
}

fn deadline_check(deadline: Instant) -> Result<()> {
    if Instant::now() > deadline {
        return Err(Error::new(
            "E_TIMEOUT",
            "tree",
            "tree verification exceeded the signed time budget",
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
    .map_err(|e| io("directory.open", e))?;
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
    .map_err(|e| io("confined.open", e))?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|e| io("confined.metadata", e))?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(state(
            "confined.type",
            "expected ordinary file/directory, not a special file",
        ));
    }
    Ok(file)
}

fn hash_file(file: &File, expected: u64, deadline: Instant) -> Result<String> {
    let mut reader = file;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        deadline_check(deadline)?;
        let n = reader.read(&mut buffer).map_err(|e| io("digest.read", e))?;
        if n == 0 {
            break;
        }
        count = add(count, n as u64)?;
        if count > expected {
            return Err(state("digest", "file grew while hashing"));
        }
        hash.update(&buffer[..n]);
    }
    if count != expected {
        return Err(state("digest", "file size changed during hashing"));
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

fn frame_rootless_metadata(hash: &mut Sha256, path: &Path) -> Result<()> {
    // umoci's inert UID/GID bookkeeping; never interpreted as runtime authority.
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

/// Hash `root` exactly as the importer did. Refuses nodes of the wrong owner,
/// device/fifo/socket nodes, and any retained node with a write or set-id bit.
pub fn digest(root: &Path, limits: &Limits) -> Result<TreeDigest> {
    let root_fd = open_directory(root)?;
    let uid = rustix::process::geteuid().as_raw();
    let deadline = Instant::now() + Duration::from_secs(limits.timeout_seconds);
    let mut hash = Sha256::new();
    frame(&mut hash, b"misa.derived-tree/v1");
    let mut bytes = 0u64;
    let mut entries = 0u64;
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .follow_root_links(false)
        .sort_by_file_name()
    {
        deadline_check(deadline)?;
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
        if entries > limits.max_entries.saturating_add(1) {
            return Err(state(
                "tree.entries",
                "materialized entry count exceeds signed policy",
            ));
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|e| io("tree.metadata", e))?;
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
            let target = fs::read_link(entry.path()).map_err(|e| io("tree.symlink", e))?;
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
            let current = file.metadata().map_err(|e| io("tree.metadata", e))?;
            let mode = current.mode() & 0o1777 & !0o222;
            if current.mode() & 0o6222 != 0 {
                return Err(state(
                    "tree.mode",
                    "retained tree gained writable or privileged mode bits; inspect offline",
                ));
            }
            if metadata.is_dir() {
                frame(&mut hash, b"directory");
                frame(&mut hash, &mode.to_be_bytes());
                frame(&mut hash, b"");
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
                let content = hash_file(&file, current.len(), deadline)?;
                frame(&mut hash, b"file");
                frame(&mut hash, &mode.to_be_bytes());
                frame(&mut hash, content.as_bytes());
            }
        } else {
            return Err(state(
                "tree.type",
                "materialization contains a device, fifo, socket or unsupported type",
            ));
        }
    }
    Ok(TreeDigest {
        digest: format!("sha256:{:x}", hash.finalize()),
        bytes,
        entries,
    })
}
