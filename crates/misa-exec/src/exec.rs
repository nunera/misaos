//! Resolution of the declared program inside the sealed rootfs, the way the kernel
//! will resolve it inside the sandbox (root = the rootfs, absolute symlinks restart
//! at the root). It rejects path escapes, missing files, non-executables, ELF
//! images for another ISA/class, interpreters of another libc family, and script
//! interpreters that do not resolve to a conforming executable. Nothing here
//! executes anything and nothing falls back to the host.
use crate::{Error, Result};
use std::{
    collections::VecDeque,
    ffi::OsStr,
    fs::{self, File},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
};

const MAX_LINKS: usize = 40;
const MAX_SCRIPT_DEPTH: usize = 4;
const PT_INTERP: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isa {
    Amd64,
    Arm64,
    I386,
}

impl Isa {
    pub fn from_platform(platform: &str) -> Result<Self> {
        match platform {
            "linux/amd64" => Ok(Self::Amd64),
            "linux/arm64" => Ok(Self::Arm64),
            "linux/386" => Ok(Self::I386),
            _ => Err(Error::new(
                "E_ABI",
                "platform",
                "unsupported root platform; no emulation is qualified",
            )),
        }
    }

    fn machine(self) -> u16 {
        match self {
            Self::Amd64 => 62,
            Self::Arm64 => 183,
            Self::I386 => 3,
        }
    }

    fn class(self) -> u8 {
        match self {
            Self::I386 => 1,
            _ => 2,
        }
    }

    /// The host kernel must be able to run this ISA natively; there is no emulator.
    pub fn host_can_run(self) -> bool {
        matches!(
            (self, std::env::consts::ARCH),
            (Self::Amd64, "x86_64") | (Self::I386, "x86_64" | "x86") | (Self::Arm64, "aarch64")
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Libc {
    Glibc,
    Musl,
}

impl Libc {
    pub fn from_family(family: &str) -> Result<Self> {
        match family {
            "glibc" => Ok(Self::Glibc),
            "musl" => Ok(Self::Musl),
            _ => Err(Error::new("E_ABI", "libcFamily", "unknown libc family")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkKind {
    Elf {
        interpreter: Option<String>,
    },
    Script {
        interpreter: String,
        argument: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub requested: String,
    pub resolved: String,
    pub kind: LinkKind,
}

/// The execution chain: the program, then each script interpreter / ELF loader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub links: Vec<Link>,
}

fn exec_error(field: &str, message: impl Into<String>) -> Error {
    Error::new("E_EXEC", field, message)
}

fn split(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|byte| *byte == b'/')
        .map(<[u8]>::to_vec)
        .collect()
}

/// Mount points the launcher covers with private tmpfs; image content there is invisible.
fn hidden_by_scratch(resolved: &str) -> bool {
    ["/tmp", "/run", "/proc", "/dev"]
        .iter()
        .any(|root| resolved == *root || resolved.starts_with(&format!("{root}/")))
}

/// Resolve `requested` with chroot semantics. `..` above the root is an escape
/// and is refused rather than clamped. Returns the host path and the canonical
/// in-root path.
pub fn resolve_in_root(rootfs: &Path, requested: &str) -> Result<(PathBuf, String)> {
    if !requested.starts_with('/') {
        return Err(exec_error("path", "in-root paths must be absolute"));
    }
    let mut pending: VecDeque<Vec<u8>> = split(requested.as_bytes()).into();
    let mut resolved: Vec<Vec<u8>> = Vec::new();
    let mut links = 0usize;
    while let Some(part) = pending.pop_front() {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            if resolved.pop().is_none() {
                return Err(Error::new(
                    "E_ESCAPE",
                    "path",
                    "path traverses above the sealed root",
                ));
            }
            continue;
        }
        let mut host = rootfs.to_path_buf();
        for component in &resolved {
            host.push(OsStr::from_bytes(component));
        }
        host.push(OsStr::from_bytes(&part));
        let metadata = fs::symlink_metadata(&host).map_err(|error| {
            exec_error(
                "path",
                format!("{requested} does not resolve inside the sealed root ({error})"),
            )
        })?;
        if metadata.file_type().is_symlink() {
            links += 1;
            if links > MAX_LINKS {
                return Err(exec_error("path", "too many levels of symbolic links"));
            }
            let target = fs::read_link(&host)
                .map_err(|e| exec_error("path", format!("cannot read symlink: {e}")))?;
            let bytes = target.as_os_str().as_bytes();
            if bytes.is_empty() {
                return Err(exec_error("path", "empty symlink target"));
            }
            if bytes[0] == b'/' {
                resolved.clear();
            }
            for component in split(bytes).into_iter().rev() {
                pending.push_front(component);
            }
        } else {
            resolved.push(part);
        }
    }
    let mut host = rootfs.to_path_buf();
    let mut canonical = String::new();
    for component in &resolved {
        host.push(OsStr::from_bytes(component));
        canonical.push('/');
        canonical.push_str(
            std::str::from_utf8(component)
                .map_err(|_| exec_error("path", "non-UTF-8 path component"))?,
        );
    }
    if canonical.is_empty() {
        canonical.push('/');
    }
    Ok((host, canonical))
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

struct ElfInfo {
    interpreter: Option<String>,
}

fn abi_error(message: &str) -> Error {
    Error::new("E_ABI", "program", message)
}

fn parse_elf(file: &File, head: &[u8], isa: Isa) -> Result<ElfInfo> {
    let class = head[4];
    let (min, phoff, phentsize, phnum) = match class {
        2 if head.len() >= 64 => (64, u64_at(head, 32), u16_at(head, 54), u16_at(head, 56)),
        1 if head.len() >= 52 => (
            52,
            u64::from(u32_at(head, 28)),
            u16_at(head, 42),
            u16_at(head, 44),
        ),
        _ => return Err(abi_error("truncated or unsupported ELF header")),
    };
    debug_assert!(head.len() >= min);
    if head[5] != 1 {
        return Err(abi_error("only little-endian ELF images are supported"));
    }
    if class != isa.class() || u16_at(head, 18) != isa.machine() {
        return Err(abi_error(
            "ELF class or machine differs from the signed root platform",
        ));
    }
    let kind = u16_at(head, 16);
    if kind != 2 && kind != 3 {
        return Err(abi_error(
            "ELF image is neither an executable nor a PIE/loader",
        ));
    }
    let entry_size = if class == 2 { 56 } else { 32 };
    if phnum == 0 {
        return Ok(ElfInfo { interpreter: None });
    }
    if usize::from(phentsize) != entry_size || phnum > 256 {
        return Err(abi_error("malformed ELF program header table"));
    }
    let mut table = vec![0u8; usize::from(phnum) * entry_size];
    file.read_exact_at(&mut table, phoff)
        .map_err(|_| abi_error("ELF program header table is truncated"))?;
    let mut interpreter = None;
    for header in table.chunks_exact(entry_size) {
        if u32_at(header, 0) != PT_INTERP {
            continue;
        }
        if interpreter.is_some() {
            return Err(abi_error("ELF image has several PT_INTERP headers"));
        }
        let (offset, size) = if class == 2 {
            (u64_at(header, 8), u64_at(header, 32))
        } else {
            (u64::from(u32_at(header, 4)), u64::from(u32_at(header, 16)))
        };
        if !(2..=4096).contains(&size) {
            return Err(abi_error("ELF interpreter path has an invalid size"));
        }
        let mut bytes = vec![0u8; size as usize];
        file.read_exact_at(&mut bytes, offset)
            .map_err(|_| abi_error("ELF interpreter path is truncated"))?;
        if bytes.pop() != Some(0) || bytes.contains(&0) {
            return Err(abi_error("ELF interpreter path is not NUL terminated"));
        }
        interpreter =
            Some(String::from_utf8(bytes).map_err(|_| abi_error("ELF interpreter is not UTF-8"))?);
    }
    Ok(ElfInfo { interpreter })
}

fn check_loader_family(interpreter: &str, libc: Libc) -> Result<()> {
    let name = interpreter.rsplit('/').next().unwrap_or(interpreter);
    let found = if name.starts_with("ld-linux") {
        Libc::Glibc
    } else if name.starts_with("ld-musl-") {
        Libc::Musl
    } else {
        return Err(abi_error(
            "ELF interpreter is not a recognised glibc or musl loader",
        ));
    };
    if found != libc {
        return Err(abi_error(
            "ELF interpreter belongs to a different libc family than the signed root",
        ));
    }
    Ok(())
}

fn resolve_executable(
    rootfs: &Path,
    requested: &str,
    isa: Isa,
    libc: Libc,
    depth: usize,
    chain: &mut Vec<Link>,
) -> Result<()> {
    let (host, resolved) = resolve_in_root(rootfs, requested)?;
    if hidden_by_scratch(&resolved) {
        return Err(exec_error(
            "program",
            format!("{resolved} lies under a launcher-provided mount and is not launchable"),
        ));
    }
    let metadata = fs::symlink_metadata(&host)
        .map_err(|e| exec_error("program", format!("cannot inspect {resolved}: {e}")))?;
    if !metadata.is_file() {
        return Err(exec_error(
            "program",
            format!("{resolved} is not a regular file"),
        ));
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(exec_error(
            "program",
            format!("{resolved} has no execute permission"),
        ));
    }
    if metadata.mode() & 0o6000 != 0 {
        return Err(exec_error(
            "program",
            format!("{resolved} carries set-id bits, which a sealed root never has"),
        ));
    }
    let file = File::open(&host)
        .map_err(|e| exec_error("program", format!("cannot open {resolved}: {e}")))?;
    let mut head = [0u8; 256];
    let count = file
        .read_at(&mut head, 0)
        .map_err(|e| exec_error("program", format!("cannot read {resolved}: {e}")))?;
    let head = &head[..count];
    if head.starts_with(b"#!") {
        if depth >= MAX_SCRIPT_DEPTH {
            return Err(exec_error(
                "program",
                "script interpreter chain is too deep",
            ));
        }
        let end = head.iter().position(|byte| *byte == b'\n').ok_or_else(|| {
            exec_error(
                "program",
                "script interpreter line is unterminated or longer than 255 bytes",
            )
        })?;
        let line = std::str::from_utf8(&head[2..end])
            .map_err(|_| exec_error("program", "script interpreter line is not UTF-8"))?
            .trim_matches([' ', '\t', '\r']);
        let (interpreter, argument) = match line.split_once([' ', '\t']) {
            Some((interpreter, rest)) => {
                let rest = rest.trim_matches([' ', '\t', '\r']);
                (interpreter, (!rest.is_empty()).then(|| rest.to_owned()))
            }
            None => (line, None),
        };
        if !interpreter.starts_with('/') {
            return Err(exec_error(
                "program",
                "script interpreter must be an absolute in-root path",
            ));
        }
        chain.push(Link {
            requested: requested.to_owned(),
            resolved,
            kind: LinkKind::Script {
                interpreter: interpreter.to_owned(),
                argument,
            },
        });
        return resolve_executable(rootfs, interpreter, isa, libc, depth + 1, chain);
    }
    if head.len() >= 20 && head.starts_with(b"\x7fELF") {
        let info = parse_elf(&file, head, isa)?;
        chain.push(Link {
            requested: requested.to_owned(),
            resolved,
            kind: LinkKind::Elf {
                interpreter: info.interpreter.clone(),
            },
        });
        if let Some(interpreter) = info.interpreter {
            check_loader_family(&interpreter, libc)?;
            let (loader_host, loader_resolved) = resolve_in_root(rootfs, &interpreter)?;
            if hidden_by_scratch(&loader_resolved) {
                return Err(exec_error(
                    "program",
                    "the ELF loader lies under a launcher-provided mount",
                ));
            }
            let loader_meta = fs::symlink_metadata(&loader_host)
                .map_err(|e| exec_error("program", format!("missing ELF loader: {e}")))?;
            if !loader_meta.is_file() || loader_meta.mode() & 0o111 == 0 {
                return Err(abi_error(
                    "the ELF loader is not an executable regular file",
                ));
            }
            let loader = File::open(&loader_host)
                .map_err(|e| exec_error("program", format!("cannot open the ELF loader: {e}")))?;
            let mut loader_head = [0u8; 64];
            let read = loader
                .read_at(&mut loader_head, 0)
                .map_err(|e| exec_error("program", format!("cannot read the ELF loader: {e}")))?;
            if read < 20 || !loader_head.starts_with(b"\x7fELF") {
                return Err(abi_error("the ELF loader is not an ELF image"));
            }
            parse_elf(&loader, &loader_head[..read], isa)?;
        }
        return Ok(());
    }
    Err(exec_error(
        "program",
        format!("{resolved} is neither an ELF image nor a #! script"),
    ))
}

/// Resolve and qualify the whole execution chain of `program` inside `rootfs`.
pub fn resolve(rootfs: &Path, program: &str, isa: Isa, libc: Libc) -> Result<Resolved> {
    if !isa.host_can_run() {
        return Err(Error::new(
            "E_ABI",
            "platform",
            "the root's ISA cannot run natively on this host and no emulator is qualified",
        ));
    }
    let mut links = Vec::new();
    resolve_executable(rootfs, program, isa, libc, 0, &mut links)?;
    Ok(Resolved { links })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn elf(isa: Isa, interpreter: Option<&str>) -> Vec<u8> {
        let mut image = vec![0u8; 64 + 56 + 64];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = isa.class();
        image[5] = 1;
        image[16..18].copy_from_slice(&3u16.to_le_bytes());
        image[18..20].copy_from_slice(&isa.machine().to_le_bytes());
        if let Some(interpreter) = interpreter {
            image[32..40].copy_from_slice(&64u64.to_le_bytes());
            image[54..56].copy_from_slice(&56u16.to_le_bytes());
            image[56..58].copy_from_slice(&1u16.to_le_bytes());
            let text_at = 64 + 56;
            let mut bytes = interpreter.as_bytes().to_vec();
            bytes.push(0);
            image[64..68].copy_from_slice(&PT_INTERP.to_le_bytes());
            image[72..80].copy_from_slice(&(text_at as u64).to_le_bytes());
            image[96..104].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            image[text_at..text_at + bytes.len()].copy_from_slice(&bytes);
        }
        image
    }

    fn put(root: &Path, relative: &str, bytes: &[u8], mode: u32) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn host_isa() -> Isa {
        if cfg!(target_arch = "aarch64") {
            Isa::Arm64
        } else {
            Isa::Amd64
        }
    }

    fn other_isa() -> Isa {
        if host_isa() == Isa::Amd64 {
            Isa::Arm64
        } else {
            Isa::Amd64
        }
    }

    fn glibc_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let isa = host_isa();
        put(
            root.path(),
            "lib/ld-linux-test.so.2",
            &elf(isa, None),
            0o755,
        );
        put(
            root.path(),
            "usr/bin/hello",
            &elf(isa, Some("/lib/ld-linux-test.so.2")),
            0o755,
        );
        root
    }

    #[test]
    fn resolves_an_elf_and_its_own_in_root_loader() {
        let root = glibc_root();
        let resolved = resolve(root.path(), "/usr/bin/hello", host_isa(), Libc::Glibc).unwrap();
        assert_eq!(resolved.links.len(), 1);
        assert_eq!(
            resolved.links[0].kind,
            LinkKind::Elf {
                interpreter: Some("/lib/ld-linux-test.so.2".into())
            }
        );
    }

    #[test]
    fn a_missing_loader_is_an_error_never_a_host_loader() {
        let root = glibc_root();
        fs::remove_file(root.path().join("lib/ld-linux-test.so.2")).unwrap();
        let error = resolve(root.path(), "/usr/bin/hello", host_isa(), Libc::Glibc).unwrap_err();
        assert_eq!(error.code, "E_EXEC");
    }

    #[test]
    fn absolute_loader_symlinks_resolve_inside_the_root_not_the_host() {
        let root = glibc_root();
        fs::create_dir_all(root.path().join("lib64")).unwrap();
        symlink(
            "/lib/ld-linux-test.so.2",
            root.path().join("lib64/ld-linux-link.so.2"),
        )
        .unwrap();
        put(
            root.path(),
            "usr/bin/linked",
            &elf(host_isa(), Some("/lib64/ld-linux-link.so.2")),
            0o755,
        );
        resolve(root.path(), "/usr/bin/linked", host_isa(), Libc::Glibc).unwrap();
        // The same absolute link must never reach a host file of that name.
        let host_only = tempfile::tempdir().unwrap();
        let hostile = root.path().join("lib64/host-link");
        symlink(host_only.path(), &hostile).unwrap();
        let error = resolve_in_root(root.path(), "/lib64/host-link/missing").unwrap_err();
        assert_eq!(error.code, "E_EXEC");
    }

    #[test]
    fn dotdot_above_the_root_is_an_escape_not_a_clamp() {
        let root = glibc_root();
        assert_eq!(
            resolve_in_root(root.path(), "/usr/../../etc/passwd")
                .unwrap_err()
                .code,
            "E_ESCAPE"
        );
        let hostile = root.path().join("usr/bin/up");
        symlink("../../../../etc/passwd", &hostile).unwrap();
        assert_eq!(
            resolve_in_root(root.path(), "/usr/bin/up")
                .unwrap_err()
                .code,
            "E_ESCAPE"
        );
    }

    #[test]
    fn mismatched_isa_class_or_loader_family_is_rejected() {
        let root = glibc_root();
        assert_eq!(
            resolve(root.path(), "/usr/bin/hello", host_isa(), Libc::Musl)
                .unwrap_err()
                .code,
            "E_ABI"
        );
        put(
            root.path(),
            "usr/bin/foreign",
            &elf(other_isa(), None),
            0o755,
        );
        assert_eq!(
            resolve(root.path(), "/usr/bin/foreign", host_isa(), Libc::Glibc)
                .unwrap_err()
                .code,
            "E_ABI"
        );
        let mut wrong_class = elf(host_isa(), None);
        wrong_class[4] = 1;
        put(root.path(), "usr/bin/class", &wrong_class, 0o755);
        assert_eq!(
            resolve(root.path(), "/usr/bin/class", host_isa(), Libc::Glibc)
                .unwrap_err()
                .code,
            "E_ABI"
        );
    }

    #[test]
    fn a_non_native_root_platform_has_no_emulation_fallback() {
        let root = glibc_root();
        let error = resolve(root.path(), "/usr/bin/hello", other_isa(), Libc::Glibc).unwrap_err();
        assert_eq!(error.code, "E_ABI");
    }

    #[test]
    fn scripts_resolve_their_interpreter_inside_the_root() {
        let root = glibc_root();
        put(
            root.path(),
            "usr/bin/tool",
            b"#!/usr/bin/hello --flag value\nbody\n",
            0o755,
        );
        let resolved = resolve(root.path(), "/usr/bin/tool", host_isa(), Libc::Glibc).unwrap();
        assert_eq!(resolved.links.len(), 2);
        assert_eq!(
            resolved.links[0].kind,
            LinkKind::Script {
                interpreter: "/usr/bin/hello".into(),
                argument: Some("--flag value".into())
            }
        );
    }

    #[test]
    fn script_interpreters_must_exist_be_absolute_and_not_loop() {
        let root = glibc_root();
        put(
            root.path(),
            "usr/bin/missing",
            b"#!/usr/bin/absent\n",
            0o755,
        );
        assert_eq!(
            resolve(root.path(), "/usr/bin/missing", host_isa(), Libc::Glibc)
                .unwrap_err()
                .code,
            "E_EXEC"
        );
        put(root.path(), "usr/bin/relative", b"#!bin/sh\n", 0o755);
        assert_eq!(
            resolve(root.path(), "/usr/bin/relative", host_isa(), Libc::Glibc)
                .unwrap_err()
                .code,
            "E_EXEC"
        );
        put(root.path(), "usr/bin/loop", b"#!/usr/bin/loop\n", 0o755);
        assert_eq!(
            resolve(root.path(), "/usr/bin/loop", host_isa(), Libc::Glibc)
                .unwrap_err()
                .code,
            "E_EXEC"
        );
    }

    #[test]
    fn non_executables_unknown_formats_and_set_id_images_are_rejected() {
        let root = glibc_root();
        put(root.path(), "usr/bin/plain", &elf(host_isa(), None), 0o644);
        put(root.path(), "usr/bin/text", b"just text\n", 0o755);
        for name in ["plain", "text"] {
            assert_eq!(
                resolve(
                    root.path(),
                    &format!("/usr/bin/{name}"),
                    host_isa(),
                    Libc::Glibc
                )
                .unwrap_err()
                .code,
                "E_EXEC",
                "{name}"
            );
        }
        put(root.path(), "usr/bin/suid", &elf(host_isa(), None), 0o755);
        let suid = root.path().join("usr/bin/suid");
        match fs::set_permissions(&suid, fs::Permissions::from_mode(0o4755)) {
            Ok(()) => assert_eq!(
                resolve(root.path(), "/usr/bin/suid", host_isa(), Libc::Glibc)
                    .unwrap_err()
                    .code,
                "E_EXEC"
            ),
            // Nix's build sandbox can prohibit creating set-id files entirely.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("cannot prepare set-id fixture: {error}"),
        }
    }

    #[test]
    fn programs_under_launcher_scratch_mounts_are_not_launchable() {
        let root = glibc_root();
        put(root.path(), "tmp/prog", &elf(host_isa(), None), 0o755);
        assert_eq!(
            resolve(root.path(), "/tmp/prog", host_isa(), Libc::Glibc)
                .unwrap_err()
                .code,
            "E_EXEC"
        );
    }
}
