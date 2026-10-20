//! BLS type 1 entries (Chapter 12): rendering and the B4 write order.
//!
//! An entry is a derived artifact (B2): a pure function of the validated manifest, the
//! host entry token (the machine ID) and the publication sequence. Blobs are
//! content-addressed and shared between generations (B5). Blobs are written and made
//! durable before the entry, whose rename is the single commit point the loader sees.
use misa_plan::{Domain, Error, Result, ValidatedRecord};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Blob {
    /// Store file the blob is copied from.
    #[serde(skip)]
    pub source: String,
    /// Path on the boot partition, `/`-rooted as in the entry.
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub file_name: String,
    pub content: String,
    pub blobs: Vec<Blob>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Publication {
    pub schema_version: &'static str,
    pub generation: String,
    pub sequence: u64,
    pub entry: String,
    pub entry_sha256: String,
    pub blobs: Vec<Blob>,
}

fn s<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .expect("schema-checked string")
}

/// First 32 hex digits of a `sha256:` digest, as used in content-addressed blob names.
fn short(digest: &str) -> &str {
    &digest["sha256:".len()..][..32]
}

/// Render the entry for a validated generation manifest.
pub fn render(manifest: &ValidatedRecord, sequence: u64) -> Result<Entry> {
    if manifest.domain() != Domain::Generation {
        return Err(Error::new(
            "E_SCHEMA",
            "/schemaVersion",
            "expected a generation manifest",
        ));
    }
    if !(1..=9_999_999_999).contains(&sequence) {
        return Err(Error::new(
            "E_BOOT_PUBLISHER",
            "sequence",
            "publication sequence is 1..=9999999999",
        ));
    }
    let m = manifest.value();
    let boot = &m["boot"];
    if s(boot, "/publisher/type") != "bls1" {
        return Err(Error::new(
            "E_BOOT_PUBLISHER",
            "/boot/publisher/type",
            "only BLS type 1 is published",
        ));
    }
    let id = &manifest.digest()["sha256:".len()..];
    let token = s(m, "/machineId");
    let mut name = format!("misa-{}-{}", &token[..8], &id[..12]);
    let tries = boot["publisher"]["tries"]
        .as_u64()
        .expect("schema-checked tries");
    if s(boot, "/publisher/selection") == "counting" {
        if !(1..=99).contains(&tries) {
            return Err(Error::new(
                "E_BOOT_PUBLISHER",
                "/boot/publisher/tries",
                "counting needs 1..=99 tries",
            ));
        }
        name.push_str(&format!("+{tries:02}-00"));
    }
    name.push_str(".conf");
    let arch = match s(boot, "/platform/arch") {
        "x86_64" => "x64",
        "aarch64" => "aa64",
        other => {
            return Err(Error::new(
                "E_BOOT_SCHEMA",
                "/boot/platform/arch",
                format!("unsupported {other}"),
            ));
        }
    };
    let kernel_sha = s(boot, "/kernel/sha256");
    let mut blobs = vec![Blob {
        source: s(boot, "/kernel/store").to_owned(),
        path: format!("/misa/{token}/k-{}/linux", short(kernel_sha)),
        sha256: kernel_sha.to_owned(),
    }];
    for part in boot["initrd"]["parts"]
        .as_array()
        .expect("schema-checked parts")
    {
        let (prefix, file) = match s(part, "/role") {
            "microcode" => ("u", "ucode.img"),
            "main" => ("i", "initrd.img"),
            _ => ("e", "extra.img"),
        };
        let sha = s(part, "/sha256");
        blobs.push(Blob {
            source: s(part, "/store").to_owned(),
            path: format!("/misa/{token}/{prefix}-{}/{file}", short(sha)),
            sha256: sha.to_owned(),
        });
    }
    let template: Vec<&str> = boot["cmdline"]["template"]
        .as_array()
        .expect("schema-checked template")
        .iter()
        .map(|t| t.as_str().expect("schema-checked token"))
        .collect();
    let mut content = format!(
        "title {}, generation {sequence}\nsort-key {}\nmachine-id {token}\nversion {sequence:010}\narchitecture {arch}\nlinux {}\n",
        format_args!("MisaOS {}", s(boot, "/publisher/titleKey")),
        s(boot, "/publisher/sortKey"),
        blobs[0].path,
    );
    for blob in &blobs[1..] {
        content.push_str(&format!("initrd {}\n", blob.path));
    }
    content.push_str(&format!(
        "options {} misa.generation={id}\n",
        template.join(" ")
    ));
    Ok(Entry {
        file_name: name,
        content,
        blobs,
    })
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    Ok(format!("sha256:{:x}", Sha256::digest(fs::read(path)?)))
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::new("E_BOOT_PUBLISH", path.display().to_string(), e.to_string())
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir).and_then(|d| d.sync_all()).map_err(io(dir))
}

/// Write `bytes` to `path` through a temporary name: write, fsync, rename, fsync dir.
fn durable_write(path: &Path, tmp: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().expect("publish paths have a parent");
    fs::create_dir_all(dir).map_err(io(dir))?;
    let mut file = File::create(tmp).map_err(io(tmp))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(io(tmp))?;
    fs::rename(tmp, path).map_err(io(path))?;
    sync_dir(dir)
}

fn on_partition(boot: &Path, path: &str) -> PathBuf {
    boot.join(path.trim_start_matches('/'))
}

/// B4: blobs first (verified against the manifest before and after the copy), then the
/// entry. Shared blobs already present with the right digest are reused.
pub fn publish(
    boot: &Path,
    manifest: &ValidatedRecord,
    entry: &Entry,
    sequence: u64,
) -> Result<Publication> {
    for blob in &entry.blobs {
        let target = on_partition(boot, &blob.path);
        if sha256_file(&target).is_ok_and(|d| d == blob.sha256) {
            continue;
        }
        let bytes = fs::read(&blob.source).map_err(io(Path::new(&blob.source)))?;
        if format!("sha256:{:x}", Sha256::digest(&bytes)) != blob.sha256 {
            return Err(Error::new(
                "E_BOOT_PUBLISH",
                blob.source.clone(),
                "store file differs from the manifest digest",
            ));
        }
        durable_write(&target, &target.with_extension("tmp"), &bytes)?;
    }
    let entries = boot.join("loader/entries");
    let path = entries.join(&entry.file_name);
    durable_write(
        &path,
        &entries.join(format!("{}.misa-tmp", entry.file_name)),
        entry.content.as_bytes(),
    )?;
    // Read-back: a detection check after the commit point, not a durability proof.
    for blob in &entry.blobs {
        let target = on_partition(boot, &blob.path);
        if sha256_file(&target).map_err(io(&target))? != blob.sha256 {
            return Err(Error::new(
                "E_BOOT_PUBLISH",
                blob.path.clone(),
                "read-back digest differs",
            ));
        }
    }
    if fs::read_to_string(&path).map_err(io(&path))? != entry.content {
        return Err(Error::new(
            "E_BOOT_PUBLISH",
            entry.file_name.clone(),
            "read-back entry differs from its render",
        ));
    }
    Ok(Publication {
        schema_version: "misa.publication/v1",
        generation: manifest.digest().to_owned(),
        sequence,
        entry: entry.file_name.clone(),
        entry_sha256: format!("sha256:{:x}", Sha256::digest(entry.content.as_bytes())),
        blobs: entry.blobs.clone(),
    })
}
