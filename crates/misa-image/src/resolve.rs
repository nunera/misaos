use crate::{
    AuthorizedLock, Error, Result, Tools,
    model::{self, Descriptor, ForeignLock, Limits, LockedImage},
    tools::run_capture,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap, fs, os::unix::process::CommandExt, path::Path, process::Command,
    time::Duration,
};

const METADATA_LIMIT: usize = misa_plan::MAX_INPUT_BYTES;

fn metadata(bytes: &[u8]) -> Result<Value> {
    let value = misa_plan::parse_strict(bytes)?;
    if !value.is_object() {
        return Err(Error::new(
            "E_LOCK",
            "metadata",
            "OCI metadata must be a JSON object",
        ));
    }
    Ok(value)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("E_LOCK", key, "OCI metadata is missing a required string"))
}

fn descriptor(value: &Value) -> Result<Descriptor> {
    let descriptor = Descriptor {
        media_type: text(value, "mediaType")?.into(),
        digest: text(value, "digest")?.into(),
        size: value.get("size").and_then(Value::as_u64).ok_or_else(|| {
            Error::new(
                "E_LOCK",
                "size",
                "OCI descriptor requires a nonnegative integral size",
            )
        })?,
    };
    model::digest_hex(&descriptor.digest)?;
    Ok(descriptor)
}

fn check_raw(bytes: &[u8], expected: &Descriptor) -> Result<()> {
    if bytes.len() as u64 != expected.size || misa_plan::hash_bytes(bytes) != expected.digest {
        return Err(Error::new(
            "E_LOCK",
            &expected.digest,
            "registry metadata does not match the locked size and digest; resolve again only after reviewing the source",
        ));
    }
    Ok(())
}

fn inspect(tools: &Tools, reference: &str, config: bool, seconds: u64) -> Result<Vec<u8>> {
    let mut command = Command::new(&tools.skopeo);
    command.args([
        "--command-timeout",
        &format!("{seconds}s"),
        "inspect",
        "--raw",
        "--no-creds",
        "--tls-verify=true",
    ]);
    if config {
        command.arg("--config");
    }
    command.arg(format!("docker://{reference}"));
    run_capture(&mut command, Duration::from_secs(seconds), METADATA_LIMIT)
}

fn split_reference(reference: &str) -> Result<&str> {
    let source = if let Some((source, digest)) = reference.split_once('@') {
        model::digest_hex(digest)?;
        source
    } else if let Some((source, tag)) = reference.rsplit_once(':') {
        if tag.is_empty()
            || tag.len() > 128
            || !tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || tag.starts_with(['.', '-'])
        {
            return Err(Error::new("E_LOCK", "reference", "invalid resolution tag"));
        }
        source
    } else {
        return Err(Error::new(
            "E_LOCK",
            "reference",
            "resolution needs an explicit tag or sha256 digest; implicit latest is not accepted",
        ));
    };
    model::validate_source(source)?;
    Ok(source)
}

/// Tags are allowed only here. Output pins both the source index and selected manifest.
pub fn resolve(
    reference: &str,
    platform: &str,
    name: &str,
    libc_family: &str,
    tools: &Tools,
) -> Result<ForeignLock> {
    model::validate_name(name)?;
    let source = split_reference(reference)?;
    if !matches!(platform, "linux/amd64" | "linux/arm64") {
        return Err(Error::new(
            "E_ABI",
            "platform",
            "choose linux/amd64 or linux/arm64; implicit variants are unsupported",
        ));
    }
    let raw = inspect(tools, reference, false, 90)?;
    if let Some((_, digest)) = reference.split_once('@')
        && misa_plan::hash_bytes(&raw) != digest
    {
        return Err(Error::new(
            "E_LOCK",
            "reference",
            "registry returned different bytes for the requested digest",
        ));
    }
    let value = metadata(&raw)?;
    let media_type = text(&value, "mediaType")?;
    let (source_index, image, manifest) = if matches!(
        media_type,
        model::OCI_INDEX | model::DOCKER_INDEX
    ) {
        let candidates = value
            .get("manifests")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Error::new("E_LOCK", "manifests", "source index has no manifest array")
            })?;
        let (os, arch) = platform.split_once('/').expect("checked platform");
        let mut matches = candidates.iter().filter(|entry| {
            entry["platform"]["os"] == os && entry["platform"]["architecture"] == arch
        });
        let selected = matches.next().ok_or_else(|| {
            Error::new(
                "E_ABI",
                "platform",
                "source index does not contain the requested platform",
            )
        })?;
        if matches.next().is_some() {
            return Err(Error::new(
                "E_ABI",
                "platform",
                "source index has ambiguous platform candidates; pin an exact compatible manifest",
            ));
        }
        if selected["platform"]
            .get("variant")
            .is_some_and(|value| value.as_str() != Some(""))
            || selected["platform"].get("os.version").is_some()
            || selected["platform"]
                .get("os.features")
                .is_some_and(|value| value.as_array().is_none_or(|items| !items.is_empty()))
        {
            return Err(Error::new(
                "E_ABI",
                "platform",
                "source requires additional platform constraints this importer does not yet qualify; no implicit variant selection",
            ));
        }
        let image = descriptor(selected)?;
        if image.size > METADATA_LIMIT as u64 {
            return Err(Error::new(
                "E_LOCK",
                "image.size",
                "selected manifest exceeds the 1 MiB metadata limit",
            ));
        }
        let raw_manifest = inspect(tools, &format!("{source}@{}", image.digest), false, 90)?;
        check_raw(&raw_manifest, &image)?;
        (
            Some(Descriptor {
                media_type: media_type.into(),
                digest: misa_plan::hash_bytes(&raw),
                size: raw.len() as u64,
            }),
            image,
            metadata(&raw_manifest)?,
        )
    } else {
        (
            None,
            Descriptor {
                media_type: media_type.into(),
                digest: misa_plan::hash_bytes(&raw),
                size: raw.len() as u64,
            },
            value,
        )
    };
    let locked = LockedImage {
        source: source.into(),
        image,
        source_index,
        libc_family: libc_family.into(),
        limits: Limits::default(),
    };
    let lock = ForeignLock {
        schema_version: 1,
        target_platform: platform.into(),
        strata: BTreeMap::from([(name.into(), locked)]),
    };
    model::validate_lock(&lock)?;
    let config = descriptor(&manifest["config"])?;
    if config.media_type != model::OCI_CONFIG || config.size > METADATA_LIMIT as u64 {
        return Err(Error::new(
            "E_CAPABILITY",
            "config",
            "require an OCI v1 config within the metadata limit",
        ));
    }
    let raw_config = inspect(
        tools,
        &format!("{source}@{}", lock.strata[name].image.digest),
        true,
        90,
    )?;
    check_raw(&raw_config, &config)?;
    let config = metadata(&raw_config)?;
    let (os, arch) = platform.split_once('/').expect("checked platform");
    if config["os"] != os
        || config["architecture"] != arch
        || config
            .get("variant")
            .is_some_and(|variant| variant.as_str() != Some(""))
    {
        return Err(Error::new(
            "E_ABI",
            "config",
            "image config does not exactly match the selected platform",
        ));
    }
    Ok(lock)
}

/// Fetches into private caller staging, never into the admitted CAS. The local
/// signature is already verified by AuthorizedLock. Skopeo's narrowly scoped
/// policy authorizes transport only; independent verification admits the bytes.
pub fn fetch(
    authorized: &AuthorizedLock,
    name: &str,
    destination: &Path,
    tools: &Tools,
) -> Result<()> {
    let locked =
        authorized.lock().strata.get(name).ok_or_else(|| {
            Error::new("E_LOCK", "stratum", "stratum is not in the approved lock")
        })?;
    let timeout = locked.limits.timeout_seconds;
    let reference = format!("{}@{}", locked.source, locked.image.digest);
    let raw_manifest = inspect(tools, &reference, false, timeout)?;
    check_raw(&raw_manifest, &locked.image)?;
    let manifest = metadata(&raw_manifest)?;
    let config = descriptor(&manifest["config"])?;
    let layers = manifest["layers"]
        .as_array()
        .ok_or_else(|| Error::new("E_LOCK", "layers", "manifest requires a layer array"))?;
    if layers.len() > 128 || config.size > METADATA_LIMIT as u64 {
        return Err(Error::new(
            "E_LOCK",
            "manifest",
            "image exceeds metadata or layer-count bounds",
        ));
    }
    let mut total = config.size;
    for value in layers {
        let layer = descriptor(value)?;
        if !matches!(layer.media_type.as_str(), model::OCI_TAR | model::OCI_GZIP) {
            return Err(Error::new(
                "E_CAPABILITY",
                "layer.mediaType",
                "only OCI tar and gzip layers are supported; no conversion is permitted",
            ));
        }
        total = total
            .checked_add(layer.size)
            .ok_or_else(|| Error::new("E_LOCK", "layers", "compressed byte count overflow"))?;
        if layer.size > locked.limits.max_blob_bytes || total > locked.limits.max_expanded_bytes {
            return Err(Error::new(
                "E_LOCK",
                "layers",
                "compressed image exceeds the approved import bounds",
            ));
        }
    }
    let raw_index = locked
        .source_index
        .as_ref()
        .map(|index| {
            let raw = inspect(
                tools,
                &format!("{}@{}", locked.source, index.digest),
                false,
                timeout,
            )?;
            check_raw(&raw, index)?;
            Ok::<_, Error>(raw)
        })
        .transpose()?;
    if destination.exists() {
        return Err(Error::new(
            "E_STATE",
            "destination",
            "fetch destination must be a new private staging layout",
        ));
    }
    let policy_directory = tempfile::tempdir().map_err(|_| {
        Error::new(
            "E_IO",
            "fetch",
            "cannot create private transport-policy directory",
        )
    })?;
    let policy_path = policy_directory.path().join("policy.json");
    let policy = json!({"default":[{"type":"reject"}],"transports":{"docker":{(locked.source.clone()):[{"type":"insecureAcceptAnything"}]}}});
    fs::write(
        &policy_path,
        serde_json::to_vec(&policy).expect("JSON policy"),
    )
    .map_err(|_| Error::new("E_IO", "fetch", "cannot write scoped transport policy"))?;
    let destination = destination
        .to_str()
        .ok_or_else(|| Error::new("E_SCHEMA", "destination", "OCI layout path must be UTF-8"))?;
    if destination.contains(':') {
        return Err(Error::new(
            "E_SCHEMA",
            "destination",
            "OCI transport paths cannot contain a colon",
        ));
    }
    let mut command = Command::new(&tools.skopeo);
    command
        .args(["--command-timeout", &format!("{timeout}s"), "--policy"])
        .arg(policy_path)
        .args([
            "copy",
            "--quiet",
            "--preserve-digests",
            "--src-no-creds",
            "--src-tls-verify=true",
            "--image-parallel-copies",
            "1",
        ])
        .arg(format!("docker://{reference}"))
        .arg(format!("oci:{destination}:locked"));
    let inherited = rustix::process::getrlimit(rustix::process::Resource::Fsize);
    let file_limit = locked
        .limits
        .max_blob_bytes
        .min(inherited.current.unwrap_or(u64::MAX))
        .min(inherited.maximum.unwrap_or(u64::MAX));
    // SAFETY: only the async-signal-safe setrlimit syscall runs after fork.
    // A lying registry cannot make even one temporary blob exceed the signed
    // per-file limit. Sequential copying bounds in-flight unverified blobs.
    unsafe {
        command.pre_exec(move || {
            rustix::process::setrlimit(
                rustix::process::Resource::Fsize,
                rustix::process::Rlimit {
                    current: Some(file_limit),
                    maximum: Some(file_limit),
                },
            )
            .map_err(std::io::Error::from)
        });
    }
    run_capture(&mut command, Duration::from_secs(timeout), 8192)?;
    if let (Some(index), Some(raw)) = (&locked.source_index, raw_index) {
        let path = Path::new(destination)
            .join("blobs/sha256")
            .join(model::digest_hex(&index.digest)?);
        fs::write(path, raw).map_err(|_| {
            Error::new(
                "E_IO",
                "sourceIndex",
                "cannot retain the original source index",
            )
        })?;
    }
    Ok(())
}
