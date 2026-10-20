//! Selected-generation verification against a mounted root (Chapter 12, V1-V12).
//!
//! At S3 the borrowed stage 1 has already switched root, so `root` is `/` in
//! production and a fixture directory in tests. V5 (embedded initrd build ID) has no
//! borrowed counterpart and is not claimed.
use crate::cmdline::{Cmdline, Selector};
use crate::elf;
use misa_plan::{Domain, Error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

pub const GENERATIONS: &str = "var/lib/misa/generations";
pub const JOURNAL: &str = "var/lib/misa/generations/journal/log";
/// Inside a host top level: the compiled init tree the adapter is started with.
pub const INIT_TREE: &str = "init-tree";

/// The running machine, as reported by `uname`.
#[derive(Debug, Clone)]
pub struct Machine {
    pub arch: String,
    pub release: String,
}

#[derive(Debug, Clone)]
pub struct Verified {
    pub generation: String,
    pub plan: String,
    pub top_level: String,
    pub init_path: String,
    pub init_sha256: String,
    pub adapter_id: String,
    pub adapter_build_id: String,
    pub selector: Selector,
    pub unlock_method: String,
    pub journal: &'static str,
    pub checks: Vec<&'static str>,
}

fn boot(code: &'static str, field: impl Into<String>, message: impl Into<String>) -> Error {
    Error::new(code, field, message)
}

/// Resolve `path` as if `root` were `/`: absolute symlink targets restart at `root` and
/// `..` never leaves it (V8 "root-confined"). Returns the host path of the result.
pub fn resolve_in_root(root: &Path, path: &str) -> Result<PathBuf> {
    let invalid = |m: &str| boot("E_BOOT_INIT_INVALID", path.to_owned(), m.to_owned());
    if !path.starts_with('/') {
        return Err(invalid("path must be absolute"));
    }
    let mut pending: Vec<OsString> = Path::new(path)
        .components()
        .rev()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.to_owned()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        })
        .collect();
    let mut current = PathBuf::new();
    let mut hops = 0;
    while let Some(name) = pending.pop() {
        if name == ".." {
            current.pop();
            continue;
        }
        let candidate = current.join(&name);
        let host = root.join(&candidate);
        let meta =
            fs::symlink_metadata(&host).map_err(|_| invalid("a path component is missing"))?;
        if meta.file_type().is_symlink() {
            hops += 1;
            if hops > 40 {
                return Err(invalid("too many symbolic links"));
            }
            let target = fs::read_link(&host).map_err(|_| invalid("unreadable symbolic link"))?;
            if target.is_absolute() {
                current = PathBuf::new();
            }
            pending.extend(target.components().rev().filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_owned()),
                Component::ParentDir => Some("..".into()),
                _ => None,
            }));
        } else {
            current = candidate;
        }
    }
    Ok(root.join(current))
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    Ok(format!("sha256:{:x}", Sha256::digest(fs::read(path)?)))
}

fn read_record(path: &Path, domain: Domain) -> Result<misa_plan::ValidatedRecord> {
    let field = path.display().to_string();
    let bytes = fs::read(path).map_err(|e| {
        boot(
            "E_BOOT_MANIFEST_MISSING",
            field.clone(),
            format!("cannot read {}: {e}", domain.schema_version()),
        )
    })?;
    // V1: strict parse is its own failure class.
    misa_plan::parse_strict(&bytes)
        .map_err(|e| boot("E_BOOT_MANIFEST_PARSE", e.field, e.message))?;
    misa_plan::validate(&bytes, Some(domain)).map_err(|e| {
        if e.code == "E_LOCK" && e.field == "/generationId" {
            boot("E_BOOT_MANIFEST_HASH", e.field, e.message)
        } else {
            boot("E_BOOT_SCHEMA", e.field, e.message)
        }
    })
}

fn elf_machine(arch: &str) -> Option<u16> {
    match arch {
        "x86_64" => Some(62),
        "aarch64" => Some(183),
        _ => None,
    }
}

fn str_at<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .expect("schema-checked string")
}

pub fn verify(root: &Path, cmd: &Cmdline, machine: &Machine) -> Result<Verified> {
    let mut checks = Vec::new();
    let dir = root.join(GENERATIONS).join(&cmd.generation);
    // V1-V3: strict parse, schema, identity; then the command-line value.
    let generation = read_record(&dir.join("manifest.json"), Domain::Generation)?;
    if generation.digest() != format!("sha256:{}", cmd.generation) {
        return Err(boot(
            "E_BOOT_MANIFEST_HASH",
            "/generationId",
            "manifest identity differs from misa.generation",
        ));
    }
    checks.extend(["V1", "V2", "V3"]);
    let manifest = generation.value();
    let plan = read_record(&dir.join("plan.json"), Domain::Plan)?;
    if plan.digest() != str_at(manifest, "/planDigest") {
        return Err(boot(
            "E_BOOT_MANIFEST_HASH",
            "/planDigest",
            "plan record differs from the manifest's planDigest",
        ));
    }
    let boot_record = &manifest["boot"];
    // V4
    if str_at(boot_record, "/platform/arch") != machine.arch {
        return Err(boot(
            "E_BOOT_ARCH",
            "/boot/platform/arch",
            "manifest architecture differs from the running machine",
        ));
    }
    checks.push("V4");
    // V6
    let uname = str_at(boot_record, "/kernel/uname");
    if uname != machine.release {
        return Err(boot(
            "E_BOOT_KERNEL_MISMATCH",
            "/boot/kernel/uname",
            format!("running {} but the manifest names {uname}", machine.release),
        ));
    }
    let modules = resolve_in_root(
        root,
        &format!("{}/{uname}", str_at(boot_record, "/modules/dir")),
    )
    .map_err(|_| {
        boot(
            "E_BOOT_KERNEL_MISMATCH",
            "/boot/modules/dir",
            "module tree for the running kernel is missing",
        )
    })?;
    if !modules.is_dir() {
        return Err(boot(
            "E_BOOT_KERNEL_MISMATCH",
            "/boot/modules/dir",
            "module tree is not a directory",
        ));
    }
    checks.push("V6");
    // V7
    let selector = Selector {
        kind: str_at(boot_record, "/root/selector/kind").to_owned(),
        value: str_at(boot_record, "/root/selector/value").to_owned(),
    };
    if selector != cmd.root {
        return Err(boot(
            "E_BOOT_ROOT_SELECTOR",
            "misa.root",
            format!(
                "command line selects {} but the manifest selects {}",
                cmd.root.render(),
                selector.render()
            ),
        ));
    }
    checks.push("V7");
    // V8
    let init_path = str_at(boot_record, "/init/path");
    let init = resolve_in_root(root, init_path)?;
    let meta = fs::metadata(&init)
        .map_err(|_| boot("E_BOOT_INIT_INVALID", "/boot/init/path", "init is missing"))?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(boot(
            "E_BOOT_INIT_INVALID",
            "/boot/init/path",
            "init is not an executable regular file",
        ));
    }
    checks.push("V8");
    // V9
    let bytes = fs::read(&init).map_err(|_| {
        boot(
            "E_BOOT_INIT_INVALID",
            "/boot/init/path",
            "init is unreadable",
        )
    })?;
    let init_sha256 = format!("sha256:{:x}", Sha256::digest(&bytes));
    if init_sha256 != str_at(boot_record, "/init/sha256") {
        return Err(boot(
            "E_BOOT_INIT_INVALID",
            "/boot/init/sha256",
            "init content differs from the manifest digest",
        ));
    }
    checks.push("V9");
    // V10
    let info = elf::inspect(&bytes)?;
    let declared = boot_record["init"]["elfMachine"]
        .as_u64()
        .expect("schema-checked machine");
    if Some(info.machine) != elf_machine(&machine.arch) || u64::from(info.machine) != declared {
        return Err(boot(
            "E_BOOT_INIT_INVALID",
            "/boot/init/elfMachine",
            format!("init is ELF machine {} on {}", info.machine, machine.arch),
        ));
    }
    if let Some(interpreter) = &info.interpreter {
        let found = resolve_in_root(root, interpreter)
            .ok()
            .and_then(|p| fs::metadata(p).ok())
            .is_some_and(|m| m.is_file());
        if !found {
            return Err(boot(
                "E_BOOT_INIT_INVALID",
                "/boot/init/path",
                format!("ELF interpreter {interpreter} is missing"),
            ));
        }
    }
    checks.push("V10");
    // V11, and the adapter tree the init is started with.
    let top_level = str_at(plan.value(), "/host/topLevel");
    let top = resolve_in_root(root, top_level)
        .ok()
        .filter(|p| p.is_dir())
        .ok_or_else(|| {
            boot(
                "E_BOOT_CLOSURE_MISSING",
                "/host/topLevel",
                "host closure root is missing",
            )
        })?;
    let adapter_build_id = str_at(boot_record, "/init/adapterBuildId");
    match sha256_file(&top.join(INIT_TREE).join("tree.json")) {
        Ok(digest) if digest == adapter_build_id => {}
        _ => {
            return Err(boot(
                "E_BOOT_INIT_INVALID",
                "/boot/init/adapterBuildId",
                "the closure's compiled init tree is not the manifest's adapter build",
            ));
        }
    }
    checks.push("V11");
    // V12: the journal format arrives with the publication transaction; absence is legal.
    let journal = match fs::metadata(root.join(JOURNAL)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "absent",
        Ok(meta) if meta.is_file() && fs::File::open(root.join(JOURNAL)).is_ok() => "present",
        _ => "unreadable",
    };
    checks.push("V12");
    Ok(Verified {
        generation: generation.digest().to_owned(),
        plan: plan.digest().to_owned(),
        top_level: top_level.to_owned(),
        init_path: init_path.to_owned(),
        init_sha256,
        adapter_id: str_at(boot_record, "/init/adapterId").to_owned(),
        adapter_build_id: adapter_build_id.to_owned(),
        selector,
        unlock_method: str_at(boot_record, "/unlock/method").to_owned(),
        journal,
        checks,
    })
}
