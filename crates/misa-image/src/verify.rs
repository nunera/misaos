//! Read-only OCI verification and archive preflight; never extracts an entry.
use crate::model::{
    DOCKER_INDEX, Descriptor, Limits, LockedImage, OCI_CONFIG, OCI_GZIP, OCI_INDEX, OCI_MANIFEST,
    OCI_TAR, digest_hex,
};
use crate::{Error, Result};
use flate2::read::MultiGzDecoder;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const DOCKER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
const JSON_LIMIT: u64 = misa_plan::MAX_INPUT_BYTES as u64;
const EXTENSION_LIMIT: u64 = 64 * 1024;
const MAX_DEPTH: usize = 64;

/// Evidence of a complete read-only preflight, not an authorization or an extraction.
/// Construction stays inside this crate so callers cannot manufacture verification.
#[derive(Debug)]
pub struct VerifiedImage {
    pub(crate) descriptors: Vec<Descriptor>,
    pub(crate) manifest: Descriptor,
    pub(crate) expanded_bytes: u64,
    pub(crate) entries: u64,
    pub(crate) stripped_modes: u64,
}

// OCI sizes are JSON integers, not the decimal strings used in a Misa lock.
// Standard metadata (annotations, history, embedded data, URLs) is not executed or fetched.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireDescriptor {
    media_type: String,
    digest: String,
    size: u64,
    platform: Option<Platform>,
}

impl WireDescriptor {
    fn descriptor(&self) -> Result<Descriptor> {
        digest_hex(&self.digest)?;
        Ok(Descriptor {
            media_type: self.media_type.clone(),
            digest: self.digest.clone(),
            size: self.size,
        })
    }
}

#[derive(Deserialize)]
struct Platform {
    os: String,
    architecture: String,
    variant: Option<String>,
    #[serde(rename = "os.version")]
    os_version: Option<String>,
    #[serde(rename = "os.features")]
    os_features: Option<Vec<String>>,
    features: Option<Vec<String>>,
}

impl Platform {
    fn matches(&self, target: &str) -> bool {
        target
            .split_once('/')
            .is_some_and(|(os, arch)| self.os == os && self.architecture == arch)
    }

    fn check(&self, target: &str, artifact: &str) -> Result<()> {
        if !self.matches(target)
            || self.variant.as_ref().is_some_and(|v| !v.is_empty())
            || self.os_version.as_ref().is_some_and(|v| !v.is_empty())
            || self.os_features.as_ref().is_some_and(|v| !v.is_empty())
            || self.features.as_ref().is_some_and(|v| !v.is_empty())
        {
            return Err(fail(
                "E_ABI",
                artifact,
                "platform-mismatch or unrecorded platform requirements",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u64,
    media_type: Option<String>,
    manifests: Vec<WireDescriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u64,
    media_type: String,
    config: WireDescriptor,
    layers: Vec<WireDescriptor>,
    artifact_type: Option<String>,
    subject: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Config {
    #[serde(flatten)]
    platform: Platform,
    rootfs: Rootfs,
}

#[derive(Deserialize)]
struct Rootfs {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LayoutMarker {
    image_layout_version: String,
}

fn fail(code: &'static str, artifact: &str, rule: &str) -> Error {
    Error::new(
        code,
        artifact,
        format!("{rule}; obtain a conforming image and explicitly admit its exact lock"),
    )
}

fn parse<T: DeserializeOwned>(bytes: &[u8], artifact: &str) -> Result<T> {
    let value = misa_plan::parse_strict(bytes).map_err(|_| {
        fail(
            "E_SCHEMA",
            artifact,
            "invalid strict OCI JSON (unique keys, bounded depth and integral numbers required)",
        )
    })?;
    serde_json::from_value(value)
        .map_err(|_| fail("E_SCHEMA", artifact, "invalid OCI metadata shape"))
}

struct Budget<'a> {
    limits: &'a Limits,
    deadline: Instant,
    expanded: u64,
    entries: u64,
    stripped_modes: u64,
}

impl Budget<'_> {
    fn check(&self, artifact: &str) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(fail(
                "E_BUILD",
                artifact,
                "verification wall-time limit exceeded",
            ));
        }
        Ok(())
    }

    fn entry(&mut self, artifact: &str) -> Result<()> {
        self.check(artifact)?;
        self.entries = self
            .entries
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_entries)
            .ok_or_else(|| fail("E_BUILD", artifact, "archive entry-count limit exceeded"))?;
        Ok(())
    }
}

/// Validate exact raw blobs, the platform/descriptor chain, and every layer before
/// materialization. Requires Linux openat2; there is no weaker path-based fallback.
pub fn verify_layout(layout: &Path, locked: &LockedImage, platform: &str) -> Result<VerifiedImage> {
    if !matches!(platform, "linux/amd64" | "linux/arm64") {
        return Err(fail("E_ABI", "targetPlatform", "unsupported platform"));
    }
    digest_hex(&locked.image.digest)?;
    if !matches!(
        locked.image.media_type.as_str(),
        OCI_MANIFEST | DOCKER_MANIFEST
    ) {
        return Err(fail(
            "E_CAPABILITY",
            &locked.image.digest,
            "unsupported manifest media type",
        ));
    }
    let limits = &locked.limits;
    if [
        limits.max_blob_bytes,
        limits.max_expanded_bytes,
        limits.max_file_bytes,
        limits.max_entries,
        limits.max_path_bytes,
        limits.max_expansion_ratio,
        limits.timeout_seconds,
    ]
    .contains(&0)
    {
        return Err(fail(
            "E_BUILD",
            &locked.image.digest,
            "verification limits must be positive",
        ));
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(limits.timeout_seconds))
        .ok_or_else(|| {
            fail(
                "E_BUILD",
                &locked.image.digest,
                "invalid verification deadline",
            )
        })?;
    let mut budget = Budget {
        limits,
        deadline,
        expanded: 0,
        entries: 0,
        stripped_modes: 0,
    };
    // Absolute caller paths are allowed for the anchor, but not symlink components.
    // NO_XDEV is applied beneath this anchor (not across caller mountpoints above it).
    let root: File = rustix::fs::openat2(
        rustix::fs::CWD,
        layout,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| {
        fail(
            "E_CAPABILITY",
            "layout",
            "cannot open non-symlink layout directory with openat2",
        )
    })?
    .into();
    let marker: LayoutMarker = parse(&small_file(&root, "oci-layout", &budget)?, "oci-layout")?;
    if marker.image_layout_version != "1.0.0" {
        return Err(fail(
            "E_SCHEMA",
            "oci-layout",
            "unsupported OCI layout version",
        ));
    }
    let index: Index = parse(&small_file(&root, "index.json", &budget)?, "index.json")?;
    check_index(&index, None, "index.json")?;
    let selected = select_locked(&index, &locked.image, "index.json")?;
    if let Some(found) = &selected.platform {
        found.check(platform, &locked.image.digest)?;
    }

    let mut descriptors = BTreeMap::new();
    if let Some(source) = &locked.source_index {
        if !matches!(source.media_type.as_str(), OCI_INDEX | DOCKER_INDEX) {
            return Err(fail(
                "E_CAPABILITY",
                "sourceIndex",
                "unsupported source index media type",
            ));
        }
        let source_index: Index = parse(&json_blob(&root, source, &budget)?, &source.digest)?;
        check_index(&source_index, Some(&source.media_type), &source.digest)?;
        let selected = select_locked(&source_index, &locked.image, &source.digest)?;
        selected
            .platform
            .as_ref()
            .ok_or_else(|| {
                fail(
                    "E_ABI",
                    &source.digest,
                    "source index selection lacks a recorded platform",
                )
            })?
            .check(platform, &source.digest)?;
        if source_index
            .manifests
            .iter()
            .filter(|d| d.platform.as_ref().is_some_and(|p| p.matches(platform)))
            .count()
            != 1
        {
            return Err(fail(
                "E_ABI",
                &source.digest,
                "ambiguous platform selection in source index",
            ));
        }
        remember(&mut descriptors, source.clone())?;
    }
    let manifest: Manifest = parse(
        &json_blob(&root, &locked.image, &budget)?,
        &locked.image.digest,
    )?;
    if manifest.schema_version != 2
        || manifest.media_type != locked.image.media_type
        || manifest.artifact_type.is_some()
        || manifest.subject.is_some()
    {
        return Err(fail(
            "E_SCHEMA",
            &locked.image.digest,
            "expected an image manifest with matching schema/media type, not an artifact",
        ));
    }
    remember(&mut descriptors, locked.image.clone())?;
    let config_descriptor = manifest.config.descriptor()?;
    if !matches!(
        config_descriptor.media_type.as_str(),
        OCI_CONFIG | DOCKER_CONFIG
    ) {
        return Err(fail(
            "E_CAPABILITY",
            &config_descriptor.digest,
            "unsupported image config media type",
        ));
    }
    if let Some(p) = &manifest.config.platform {
        p.check(platform, &config_descriptor.digest)?;
    }
    let config: Config = parse(
        &json_blob(&root, &config_descriptor, &budget)?,
        &config_descriptor.digest,
    )?;
    config.platform.check(platform, &config_descriptor.digest)?;
    if config.rootfs.kind != "layers" || config.rootfs.diff_ids.len() != manifest.layers.len() {
        return Err(fail(
            "E_TRUST",
            &config_descriptor.digest,
            "rootfs layer count/type does not match manifest",
        ));
    }
    remember(&mut descriptors, config_descriptor)?;
    let mut view = BTreeMap::new();
    for (wire, diff_id) in manifest.layers.iter().zip(&config.rootfs.diff_ids) {
        digest_hex(diff_id)?;
        let descriptor = wire.descriptor()?;
        if !matches!(
            descriptor.media_type.as_str(),
            OCI_TAR | OCI_GZIP | DOCKER_GZIP
        ) {
            return Err(fail(
                "E_CAPABILITY",
                &descriptor.digest,
                "only raw tar and gzip tar layers are supported",
            ));
        }
        if let Some(p) = &wire.platform {
            p.check(platform, &descriptor.digest)?;
        }
        let file = checked_blob(&root, &descriptor, &budget)?;
        scan_layer(file, &descriptor, diff_id, &mut budget, &mut view)?;
        remember(&mut descriptors, descriptor)?;
    }
    budget.check(&locked.image.digest)?;
    Ok(VerifiedImage {
        descriptors: descriptors.into_values().collect(),
        manifest: locked.image.clone(),
        expanded_bytes: budget.expanded,
        entries: budget.entries,
        stripped_modes: budget.stripped_modes,
    })
}

fn check_index(index: &Index, expected: Option<&str>, artifact: &str) -> Result<()> {
    if index.schema_version != 2
        || index
            .media_type
            .as_deref()
            .is_some_and(|m| !matches!(m, OCI_INDEX | DOCKER_INDEX))
        || expected.is_some_and(|m| index.media_type.as_deref() != Some(m))
    {
        return Err(fail(
            "E_SCHEMA",
            artifact,
            "index schema/media type mismatch",
        ));
    }
    for descriptor in &index.manifests {
        descriptor.descriptor()?;
    }
    Ok(())
}

fn select_locked<'a>(
    index: &'a Index,
    locked: &Descriptor,
    artifact: &str,
) -> Result<&'a WireDescriptor> {
    let mut found = index.manifests.iter().filter(|d| d.digest == locked.digest);
    let selected = found.next().ok_or_else(|| {
        fail(
            "E_LOCK",
            artifact,
            "index does not select the locked manifest",
        )
    })?;
    if found.next().is_some() || selected.descriptor()? != *locked {
        return Err(fail(
            "E_LOCK",
            artifact,
            "duplicate or inconsistent locked manifest descriptor in index",
        ));
    }
    Ok(selected)
}

fn remember(descriptors: &mut BTreeMap<String, Descriptor>, descriptor: Descriptor) -> Result<()> {
    if let Some(previous) = descriptors.get(&descriptor.digest) {
        if previous != &descriptor {
            return Err(fail(
                "E_TRUST",
                &descriptor.digest,
                "conflicting descriptors for the same digest",
            ));
        }
    } else {
        descriptors.insert(descriptor.digest.clone(), descriptor);
    }
    Ok(())
}

fn confined_file(root: &File, path: &str) -> Result<File> {
    let file: File = rustix::fs::openat2(
        root,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| {
        fail(
            "E_PATH_OWNER",
            "layout",
            "layout file is missing, crosses a mount, or is not confined",
        )
    })?
    .into();
    if !file
        .metadata()
        .map_err(|_| fail("E_IO", "layout", "cannot inspect layout file"))?
        .is_file()
    {
        return Err(fail(
            "E_PATH_OWNER",
            "layout",
            "layout member must be a regular file",
        ));
    }
    Ok(file)
}

fn small_file(root: &File, name: &str, budget: &Budget<'_>) -> Result<Vec<u8>> {
    let file = confined_file(root, name)?;
    read_small(
        file,
        budget.limits.max_blob_bytes.min(JSON_LIMIT),
        budget.deadline,
        name,
    )
}

fn read_small(mut file: File, limit: u64, deadline: Instant, artifact: &str) -> Result<Vec<u8>> {
    let size = file
        .metadata()
        .map_err(|_| fail("E_IO", artifact, "cannot inspect JSON blob"))?
        .len();
    if size > limit {
        return Err(fail("E_BUILD", artifact, "OCI JSON byte limit exceeded"));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(fail(
                "E_BUILD",
                artifact,
                "verification wall-time limit exceeded",
            ));
        }
        let n = file
            .read(&mut chunk)
            .map_err(|_| fail("E_IO", artifact, "cannot read OCI JSON"))?;
        if n == 0 {
            break;
        }
        if bytes.len() as u64 + n as u64 > limit {
            return Err(fail("E_BUILD", artifact, "OCI JSON byte limit exceeded"));
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    Ok(bytes)
}

fn blob_file(root: &File, descriptor: &Descriptor, budget: &Budget<'_>) -> Result<File> {
    let hex = digest_hex(&descriptor.digest)?;
    budget.check(&descriptor.digest)?;
    if descriptor.size > budget.limits.max_blob_bytes {
        return Err(fail(
            "E_BUILD",
            &descriptor.digest,
            "compressed blob byte limit exceeded",
        ));
    }
    let file = confined_file(root, &format!("blobs/sha256/{hex}"))?;
    if file
        .metadata()
        .map_err(|_| fail("E_IO", &descriptor.digest, "cannot inspect blob"))?
        .len()
        != descriptor.size
    {
        return Err(fail(
            "E_TRUST",
            &descriptor.digest,
            "raw descriptor size mismatch",
        ));
    }
    Ok(file)
}

fn json_blob(root: &File, descriptor: &Descriptor, budget: &Budget<'_>) -> Result<Vec<u8>> {
    let file = blob_file(root, descriptor, budget)?;
    let bytes = read_small(
        file,
        descriptor.size.min(JSON_LIMIT),
        budget.deadline,
        &descriptor.digest,
    )?;
    if bytes.len() as u64 != descriptor.size || hash(&bytes) != descriptor.digest {
        return Err(fail(
            "E_TRUST",
            &descriptor.digest,
            "raw descriptor SHA256/size mismatch",
        ));
    }
    Ok(bytes)
}

fn checked_blob(root: &File, descriptor: &Descriptor, budget: &Budget<'_>) -> Result<File> {
    let mut reader = HashedReader::new(
        blob_file(root, descriptor, budget)?,
        descriptor.size,
        budget.deadline,
    );
    drain(&mut reader).map_err(|_| {
        fail(
            "E_BUILD",
            &descriptor.digest,
            "bounded raw blob read failed",
        )
    })?;
    if reader.bytes != descriptor.size || reader.digest() != descriptor.digest {
        return Err(fail(
            "E_TRUST",
            &descriptor.digest,
            "raw descriptor SHA256/size mismatch",
        ));
    }
    reader
        .inner
        .seek(SeekFrom::Start(0))
        .map_err(|_| fail("E_IO", &descriptor.digest, "cannot rewind verified blob"))?;
    Ok(reader.inner)
}

fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn drain(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0u8; 64 * 1024];
    let mut total = 0;
    loop {
        let n = reader.read(&mut bytes)?;
        if n == 0 {
            return Ok(total);
        }
        total += n as u64;
    }
}

struct HashedReader<R> {
    inner: R,
    hash: Sha256,
    bytes: u64,
    limit: u64,
    deadline: Instant,
}

impl<R> HashedReader<R> {
    fn new(inner: R, limit: u64, deadline: Instant) -> Self {
        Self {
            inner,
            hash: Sha256::new(),
            bytes: 0,
            limit,
            deadline,
        }
    }
    fn digest(&self) -> String {
        format!("sha256:{:x}", self.hash.clone().finalize())
    }
}

impl<R: Read> Read for HashedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::other("verification deadline exceeded"));
        }
        // One lookahead byte distinguishes exact-limit EOF from an oversized stream.
        let len = bytes.len().min(
            self.limit
                .saturating_sub(self.bytes)
                .saturating_add(1)
                .min(usize::MAX as u64) as usize,
        );
        let n = self.inner.read(&mut bytes[..len])?;
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| io::Error::other("verification byte/expansion limit exceeded"))?;
        self.hash.update(&bytes[..n]);
        Ok(n)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Directory,
    Regular,
    Symlink,
}

enum Operation {
    Entry {
        path: String,
        kind: Kind,
        hardlink: Option<String>,
    },
    Whiteout {
        path: String,
        target: String,
        opaque: bool,
    },
}

#[derive(Default)]
struct Extensions {
    path: Option<Vec<u8>>,
    link: Option<Vec<u8>>,
    pax: bool,
    gnu: bool,
}

fn scan_layer(
    file: File,
    descriptor: &Descriptor,
    diff_id: &str,
    budget: &mut Budget<'_>,
    view: &mut BTreeMap<String, Kind>,
) -> Result<()> {
    if descriptor.media_type == OCI_TAR {
        scan_archive(
            file,
            descriptor,
            diff_id,
            budget,
            view,
            |_, digest, bytes| {
                if digest != descriptor.digest || bytes != descriptor.size {
                    return Err(fail(
                        "E_TRUST",
                        &descriptor.digest,
                        "raw layer changed during verification",
                    ));
                }
                Ok(())
            },
        )
    } else {
        let input = MultiGzDecoder::new(HashedReader::new(file, descriptor.size, budget.deadline));
        scan_archive(input, descriptor, diff_id, budget, view, |decoder, _, _| {
            let compressed = decoder.into_inner();
            if compressed.bytes != descriptor.size || compressed.digest() != descriptor.digest {
                return Err(fail(
                    "E_TRUST",
                    &descriptor.digest,
                    "compressed layer changed during verification",
                ));
            }
            Ok(())
        })
    }
}

fn scan_archive<R: Read>(
    input: R,
    descriptor: &Descriptor,
    diff_id: &str,
    budget: &mut Budget<'_>,
    view: &mut BTreeMap<String, Kind>,
    finish: impl FnOnce(R, &str, u64) -> Result<()>,
) -> Result<()> {
    let artifact = descriptor.digest.as_str();
    let expanded_limit = budget
        .limits
        .max_expanded_bytes
        .saturating_sub(budget.expanded)
        .min(
            descriptor
                .size
                .saturating_mul(budget.limits.max_expansion_ratio),
        );
    let mut archive = tar::Archive::new(HashedReader::new(input, expanded_limit, budget.deadline));
    let mut names = BTreeSet::new();
    let mut operations = Vec::new();
    let mut extensions = Extensions::default();
    let mut last_end = 0u64;
    for entry in archive
        .entries()
        .map_err(|_| fail("E_BUILD", artifact, "cannot read tar entries"))?
        .raw(true)
    {
        budget.entry(artifact)?;
        let mut entry =
            entry.map_err(|_| fail("E_BUILD", artifact, "invalid tar header or bounded stream"))?;
        let header = entry.header();
        let size = header
            .size()
            .map_err(|_| fail("E_BUILD", artifact, "invalid tar size"))?;
        if size > budget.limits.max_file_bytes {
            return Err(fail(
                "E_BUILD",
                artifact,
                "archive per-file byte limit exceeded",
            ));
        }
        last_end = entry
            .raw_header_position()
            .checked_add(512)
            .and_then(|offset| {
                size.checked_add(511)
                    .map(|size| size / 512 * 512)
                    .and_then(|size| offset.checked_add(size))
            })
            .ok_or_else(|| fail("E_BUILD", artifact, "archive offset overflow"))?;
        let entry_type = header.entry_type().as_byte();
        if matches!(entry_type, b'x' | b'g' | b'L' | b'K') {
            if header.as_gnu().is_none() && header.as_ustar().is_none() {
                return Err(fail(
                    "E_BUILD",
                    artifact,
                    "extension header lacks a recognized tar format",
                ));
            }
            if size > EXTENSION_LIMIT {
                return Err(fail(
                    "E_BUILD",
                    artifact,
                    "archive extension byte limit exceeded",
                ));
            }
            let mut bytes = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut bytes)
                .map_err(|_| fail("E_BUILD", artifact, "truncated or unbounded tar extension"))?;
            if bytes.len() as u64 != size {
                return Err(fail("E_BUILD", artifact, "truncated tar extension"));
            }
            read_extension(entry_type, bytes, &mut extensions, budget.limits, artifact)?;
            continue;
        }
        let kind = match entry_type {
            0 | b'0' | b'1' => Kind::Regular,
            b'2' => Kind::Symlink,
            b'5' => Kind::Directory,
            _ => {
                return Err(fail(
                    "E_BUILD",
                    artifact,
                    "special, sparse or unsupported archive entry type",
                ));
            }
        };
        // Reject hidden suffixes after NUL instead of disagreeing with another tar parser.
        let raw = header.as_bytes();
        clean_field(&raw[..100], artifact)?;
        clean_field(&raw[157..257], artifact)?;
        if header.as_ustar().is_some() {
            clean_field(&raw[345..500], artifact)?;
        }
        let mode = header
            .mode()
            .map_err(|_| fail("E_BUILD", artifact, "invalid archive mode"))?;
        if mode & !0o7777 != 0 {
            return Err(fail(
                "E_BUILD",
                artifact,
                "archive mode contains unsupported file-type bits",
            ));
        }
        header
            .uid()
            .and_then(|_| header.gid())
            .and_then(|_| header.mtime())
            .map_err(|_| {
                fail(
                    "E_BUILD",
                    artifact,
                    "invalid archive ownership/time metadata",
                )
            })?;
        let path_bytes = extensions
            .path
            .take()
            .unwrap_or_else(|| header.path_bytes().into_owned());
        let link_bytes = extensions
            .link
            .take()
            .or_else(|| header.link_name_bytes().map(|v| v.into_owned()));
        extensions = Extensions::default();
        let path = normal_path(
            &path_bytes,
            kind == Kind::Directory,
            budget.limits,
            artifact,
        )?;
        if !names.insert(path.clone()) {
            return Err(fail(
                "E_BUILD",
                artifact,
                "duplicate archive path in one layer",
            ));
        }
        if entry_type != 0 && entry_type != b'0' && size != 0 {
            return Err(fail(
                "E_BUILD",
                artifact,
                "non-regular entry carries an ambiguous data payload",
            ));
        }
        if kind != Kind::Symlink
            && entry_type != b'1'
            && link_bytes.as_ref().is_some_and(|v| !v.is_empty())
        {
            return Err(fail(
                "E_BUILD",
                artifact,
                "unexpected link target on a non-link entry",
            ));
        }
        if mode & 0o6000 != 0 {
            budget.stripped_modes += 1;
        }
        if path.is_empty() {
            // Audited exception for Debian's root '.' directory header: metadata only.
            // No write/chmod/chown operation is represented in the layer model.
            continue;
        }
        let basename = path.rsplit('/').next().unwrap_or_default();
        if let Some(target) = basename.strip_prefix(".wh.") {
            if !matches!(entry_type, 0 | b'0') || size != 0 || target.is_empty() {
                return Err(fail(
                    "E_BUILD",
                    artifact,
                    "whiteout must be an empty regular marker with a nonempty target",
                ));
            }
            let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            let opaque = basename == ".wh..wh..opq";
            if !opaque && (target == "." || target == ".." || target.starts_with(".wh.")) {
                return Err(fail(
                    "E_BUILD",
                    artifact,
                    "invalid or ambiguous whiteout target",
                ));
            }
            let target = if opaque {
                parent.to_owned()
            } else if parent.is_empty() {
                target.to_owned()
            } else {
                format!("{parent}/{target}")
            };
            operations.push(Operation::Whiteout {
                path,
                target,
                opaque,
            });
            continue;
        }
        let hardlink = if entry_type == b'1' {
            Some(normal_path(
                link_bytes.as_deref().unwrap_or_default(),
                false,
                budget.limits,
                artifact,
            )?)
        } else {
            if kind == Kind::Symlink {
                check_symlink(
                    &path,
                    link_bytes.as_deref().unwrap_or_default(),
                    budget.limits,
                    artifact,
                )?;
            }
            None
        };
        let consumed = drain(&mut entry)
            .map_err(|_| fail("E_BUILD", artifact, "truncated or unbounded archive entry"))?;
        if consumed != size {
            return Err(fail("E_BUILD", artifact, "truncated archive file payload"));
        }
        operations.push(Operation::Entry {
            path,
            kind,
            hardlink,
        });
    }
    if extensions.pax || extensions.gnu {
        return Err(fail(
            "E_BUILD",
            artifact,
            "dangling archive extension without an entry",
        ));
    }
    let mut reader = archive.into_inner();
    // tar stops at the first zero block. Require a second, aligned end marker;
    // reject hidden concatenated archives while hashing ALL trailing zero padding.
    if reader.bytes != last_end.saturating_add(512) {
        return Err(fail("E_BUILD", artifact, "tar lacks a complete end marker"));
    }
    let mut padding = [0u8; 64 * 1024];
    let mut trailing = 0u64;
    loop {
        let n = reader.read(&mut padding).map_err(|_| {
            fail(
                "E_BUILD",
                artifact,
                "invalid gzip trailer or expanded byte/ratio/time limit exceeded",
            )
        })?;
        if n == 0 {
            break;
        }
        if padding[..n].iter().any(|b| *b != 0) {
            return Err(fail(
                "E_BUILD",
                artifact,
                "nonzero data after tar end marker",
            ));
        }
        trailing += n as u64;
    }
    if trailing < 512 || !reader.bytes.is_multiple_of(512) {
        return Err(fail(
            "E_BUILD",
            artifact,
            "tar end padding is truncated or unaligned",
        ));
    }
    let expanded_digest = reader.digest();
    if expanded_digest != diff_id {
        return Err(fail(
            "E_TRUST",
            artifact,
            "uncompressed rootfs.diff_ids SHA256 mismatch",
        ));
    }
    finish(reader.inner, &expanded_digest, reader.bytes)?;
    budget.expanded += reader.bytes;
    drop(names);
    apply_layer(view, operations, budget, artifact)
}

fn clean_field(bytes: &[u8], artifact: &str) -> Result<()> {
    if let Some(nul) = bytes.iter().position(|b| *b == 0)
        && bytes[nul..].iter().any(|b| *b != 0)
    {
        return Err(fail(
            "E_BUILD",
            artifact,
            "ambiguous NUL-terminated archive field",
        ));
    }
    Ok(())
}

fn normal_path(bytes: &[u8], directory: bool, limits: &Limits, artifact: &str) -> Result<String> {
    if bytes.len() as u64 > limits.max_path_bytes {
        return Err(fail(
            "E_BUILD",
            artifact,
            "archive path byte limit exceeded",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        fail(
            "E_CAPABILITY",
            artifact,
            "non-UTF-8 archive names are unsupported",
        )
    })?;
    if directory && matches!(text, "." | "./") {
        return Ok(String::new());
    }
    // A single terminal slash is the conventional directory spelling, not an
    // extra path component. No other normalization hides an unsafe component.
    let path = if directory {
        text.strip_suffix('/').unwrap_or(text)
    } else {
        text
    };
    if path.is_empty()
        || path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || path.split('/').count() > MAX_DEPTH
    {
        return Err(fail(
            "E_BUILD",
            artifact,
            "path-escape, empty/dot component or archive depth limit exceeded",
        ));
    }
    if path
        .rsplit_once('/')
        .is_some_and(|(parent, _)| parent.split('/').any(|part| part.starts_with(".wh.")))
    {
        return Err(fail(
            "E_BUILD",
            artifact,
            "reserved whiteout name used as an archive parent",
        ));
    }
    Ok(path.to_owned())
}

fn check_symlink(path: &str, bytes: &[u8], limits: &Limits, artifact: &str) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > limits.max_path_bytes || bytes.contains(&0) {
        return Err(fail(
            "E_BUILD",
            artifact,
            "empty, NUL-containing or overlong symlink target",
        ));
    }
    let target = std::str::from_utf8(bytes).map_err(|_| {
        fail(
            "E_CAPABILITY",
            artifact,
            "non-UTF-8 symlink targets are unsupported",
        )
    })?;
    let absolute = target.starts_with('/');
    let mut depth = if absolute {
        0
    } else {
        path.bytes().filter(|b| *b == b'/').count()
    };
    let parts = target.strip_prefix('/').unwrap_or(target);
    if absolute && parts.is_empty() {
        return Ok(());
    }
    if parts.split('/').count() > MAX_DEPTH {
        return Err(fail(
            "E_BUILD",
            artifact,
            "symlink target depth limit exceeded",
        ));
    }
    for part in parts.split('/') {
        match part {
            "" => return Err(fail("E_BUILD", artifact, "empty symlink target component")),
            "." => {}
            ".." => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    fail("E_BUILD", artifact, "symlink target escapes the image root")
                })?
            }
            _ => depth += 1,
        }
        if depth > MAX_DEPTH {
            return Err(fail(
                "E_BUILD",
                artifact,
                "symlink target depth limit exceeded",
            ));
        }
    }
    Ok(())
}

fn read_extension(
    kind: u8,
    bytes: Vec<u8>,
    ext: &mut Extensions,
    limits: &Limits,
    artifact: &str,
) -> Result<()> {
    if kind == b'g' {
        return Err(fail(
            "E_CAPABILITY",
            artifact,
            "global PAX headers are unsupported",
        ));
    }
    if kind == b'L' || kind == b'K' {
        if ext.pax {
            return Err(fail(
                "E_BUILD",
                artifact,
                "conflicting GNU and PAX extensions",
            ));
        }
        ext.gnu = true;
        let slot = if kind == b'L' {
            &mut ext.path
        } else {
            &mut ext.link
        };
        if slot.is_some()
            || bytes.last() != Some(&0)
            || bytes[..bytes.len().saturating_sub(1)].contains(&0)
            || bytes.len().saturating_sub(1) as u64 > limits.max_path_bytes
        {
            return Err(fail(
                "E_BUILD",
                artifact,
                "duplicate, malformed or overlong GNU name extension",
            ));
        }
        let mut bytes = bytes;
        bytes.pop();
        *slot = Some(bytes);
        return Ok(());
    }
    if ext.gnu || ext.pax {
        return Err(fail(
            "E_BUILD",
            artifact,
            "duplicate or conflicting PAX extensions",
        ));
    }
    ext.pax = true;
    let mut seen = BTreeSet::new();
    let mut remaining = bytes.as_slice();
    while !remaining.is_empty() {
        let space = remaining
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| fail("E_BUILD", artifact, "invalid PAX record length"))?;
        let digits = &remaining[..space];
        if digits.is_empty() || digits[0] == b'0' || !digits.iter().all(u8::is_ascii_digit) {
            return Err(fail("E_BUILD", artifact, "noncanonical PAX record length"));
        }
        let len = std::str::from_utf8(digits)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|len| *len > space + 2 && *len <= remaining.len())
            .ok_or_else(|| fail("E_BUILD", artifact, "invalid PAX record length"))?;
        let record = &remaining[space + 1..len];
        if record.last() != Some(&b'\n')
            || record[..record.len() - 1].contains(&b'\n')
            || record.contains(&0)
        {
            return Err(fail("E_BUILD", artifact, "ambiguous PAX record framing"));
        }
        let record = &record[..record.len() - 1];
        let equal = record
            .iter()
            .position(|b| *b == b'=')
            .ok_or_else(|| fail("E_BUILD", artifact, "PAX record lacks a value"))?;
        let key = std::str::from_utf8(&record[..equal])
            .map_err(|_| fail("E_BUILD", artifact, "non-UTF-8 PAX key"))?;
        let value = &record[equal + 1..];
        if !seen.insert(key) || value.is_empty() {
            return Err(fail(
                "E_BUILD",
                artifact,
                "duplicate PAX key or ambiguous deletion value",
            ));
        }
        match key {
            "path" => ext.path = Some(value.to_vec()),
            "linkpath" => ext.link = Some(value.to_vec()),
            "uid" | "gid" => {
                if !value.iter().all(u8::is_ascii_digit)
                    || std::str::from_utf8(value)
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok())
                        .is_none()
                {
                    return Err(fail("E_BUILD", artifact, "unsupported PAX ownership value"));
                }
            }
            "mtime" | "atime" | "ctime" => {
                let value = std::str::from_utf8(value)
                    .map_err(|_| fail("E_BUILD", artifact, "invalid PAX timestamp"))?;
                let value = value.strip_prefix('-').unwrap_or(value);
                let (seconds, fraction) = value
                    .split_once('.')
                    .map_or((value, None), |(s, f)| (s, Some(f)));
                if seconds.is_empty()
                    || !seconds.bytes().all(|b| b.is_ascii_digit())
                    || seconds.parse::<i64>().is_err()
                    || fraction.is_some_and(|s| {
                        s.is_empty() || s.len() > 9 || !s.bytes().all(|b| b.is_ascii_digit())
                    })
                {
                    return Err(fail("E_BUILD", artifact, "unsupported PAX timestamp"));
                }
            }
            "uname" | "gname" => {
                if value.len() > 256 || std::str::from_utf8(value).is_err() {
                    return Err(fail("E_BUILD", artifact, "unsupported PAX ownership name"));
                }
            }
            _ => {
                let dangerous = key.contains("security.")
                    || key.contains("trusted.")
                    || key.contains("overlay.")
                    || key.contains("sparse")
                    || key.contains("acl");
                return Err(fail(
                    if dangerous { "E_TRUST" } else { "E_CAPABILITY" },
                    artifact,
                    "unsupported PAX metadata (xattrs, sparse files and size overrides are not admitted)",
                ));
            }
        }
        remaining = &remaining[len..];
    }
    Ok(())
}

fn parents(
    view: &mut BTreeMap<String, Kind>,
    path: &str,
    create: bool,
    budget: &Budget<'_>,
    artifact: &str,
) -> Result<()> {
    for (offset, _) in path.match_indices('/') {
        let parent = &path[..offset];
        match view.get(parent) {
            Some(Kind::Directory) => {}
            Some(_) => {
                return Err(fail(
                    "E_BUILD",
                    artifact,
                    "archive write/link traverses a symlink or non-directory parent",
                ));
            }
            None if create => {
                if view.len() as u64 >= budget.limits.max_entries {
                    return Err(fail(
                        "E_BUILD",
                        artifact,
                        "archive view-node limit exceeded (including implicit directories)",
                    ));
                }
                view.insert(parent.to_owned(), Kind::Directory);
            }
            None => {}
        }
    }
    Ok(())
}

fn remove_subtree(view: &mut BTreeMap<String, Kind>, path: &str, keep_directory: bool) {
    if path.is_empty() {
        view.clear();
        return;
    }
    if !keep_directory {
        view.remove(path);
    }
    let prefix = format!("{path}/");
    // Each removed key is visited once; avoid a whole-view scan per whiteout.
    loop {
        let next = view
            .range::<str, _>((
                std::ops::Bound::Included(prefix.as_str()),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .filter(|(key, _)| key.starts_with(&prefix))
            .map(|(key, _)| key.clone());
        match next {
            Some(key) => {
                view.remove(&key);
            }
            None => break,
        }
    }
}

fn apply_layer(
    view: &mut BTreeMap<String, Kind>,
    operations: Vec<Operation>,
    budget: &Budget<'_>,
    artifact: &str,
) -> Result<()> {
    // Pass one removes lower paths ONLY, irrespective of marker position in tar.
    // No snapshot clone is needed: no same-layer entry has been installed yet.
    for operation in &operations {
        budget.check(artifact)?;
        if let Operation::Whiteout {
            path,
            target,
            opaque,
        } = operation
        {
            parents(view, path, false, budget, artifact)?;
            if *opaque
                && !target.is_empty()
                && view
                    .get(target)
                    .is_some_and(|kind| *kind != Kind::Directory)
            {
                return Err(fail(
                    "E_BUILD",
                    artifact,
                    "opaque whiteout parent is not a directory",
                ));
            }
            remove_subtree(view, target, *opaque);
        }
    }
    // Replay markers too, without deletion, to reject traversal through a symlink
    // introduced earlier in this layer. Normal entries retain their archive order.
    for operation in operations {
        budget.check(artifact)?;
        match operation {
            Operation::Whiteout { path, .. } => parents(view, &path, false, budget, artifact)?,
            Operation::Entry {
                path,
                kind,
                hardlink,
            } => {
                parents(view, &path, true, budget, artifact)?;
                if let Some(target) = hardlink {
                    parents(view, &target, false, budget, artifact)?;
                    if target == path
                        || target
                            .strip_prefix(path.as_str())
                            .is_some_and(|suffix| suffix.starts_with('/'))
                        || view.get(&target) != Some(&Kind::Regular)
                    {
                        return Err(fail(
                            "E_BUILD",
                            artifact,
                            "hardlink target is not a previous verified regular file",
                        ));
                    }
                }
                if kind != Kind::Directory && view.get(&path) == Some(&Kind::Directory) {
                    remove_subtree(view, &path, false);
                }
                if !view.contains_key(&path) && view.len() as u64 >= budget.limits.max_entries {
                    return Err(fail(
                        "E_BUILD",
                        artifact,
                        "archive view-node limit exceeded (including implicit directories)",
                    ));
                }
                view.insert(path, kind);
            }
        }
    }
    Ok(())
}
