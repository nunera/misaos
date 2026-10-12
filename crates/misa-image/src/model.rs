use crate::{Error, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, sync::LazyLock};

pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const OCI_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
pub const OCI_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

static LOCK_SCHEMA: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/misa.lock-v1.schema.json"))
            .expect("embedded foreign-lock schema");
    jsonschema::validator_for(&schema).expect("valid embedded foreign-lock schema")
});
/// Misa byte counts are decimal strings, unlike OCI's integral descriptor sizes.
pub mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty()
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(D::Error::custom(
                "expected canonical unsigned decimal string",
            ));
        }
        text.parse()
            .map_err(|_| D::Error::custom("decimal string exceeds u64"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    #[serde(with = "decimal")]
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    #[serde(with = "decimal")]
    pub max_blob_bytes: u64,
    #[serde(with = "decimal")]
    pub max_expanded_bytes: u64,
    #[serde(with = "decimal")]
    pub max_file_bytes: u64,
    pub max_entries: u64,
    pub max_path_bytes: u64,
    pub max_expansion_ratio: u64,
    pub timeout_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 512 * 1024 * 1024,
            max_expanded_bytes: 2 * 1024 * 1024 * 1024,
            max_file_bytes: 512 * 1024 * 1024,
            max_entries: 200_000,
            max_path_bytes: 4096,
            max_expansion_ratio: 256,
            timeout_seconds: 300,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LockedImage {
    pub source: String,
    pub image: Descriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_index: Option<Descriptor>,
    pub libc_family: String,
    pub limits: Limits,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForeignLock {
    pub schema_version: u32,
    pub target_platform: String,
    pub strata: BTreeMap<String, LockedImage>,
}

pub fn parse_record<T: DeserializeOwned>(bytes: &[u8], field: &str) -> Result<T> {
    let value = misa_plan::parse_strict(bytes)?;
    serde_json::from_value(value).map_err(|_| {
        Error::new(
            "E_SCHEMA",
            field,
            "record does not match its closed wire schema",
        )
    })
}

pub fn parse_lock(bytes: &[u8]) -> Result<ForeignLock> {
    let value = misa_plan::parse_strict(bytes)?;
    LOCK_SCHEMA.validate(&value).map_err(|_| {
        Error::new(
            "E_SCHEMA",
            "lock",
            "record does not match the published closed foreign-lock schema",
        )
    })?;
    let lock = serde_json::from_value(value)
        .map_err(|_| Error::new("E_SCHEMA", "lock", "cannot decode foreign-lock record"))?;
    validate_lock(&lock)?;
    Ok(lock)
}

pub fn canonical_lock(lock: &ForeignLock) -> Result<Vec<u8>> {
    validate_lock(lock)?;
    serde_jcs::to_vec(lock).map_err(|_| Error::new("E_SCHEMA", "lock", "cannot canonicalize lock"))
}

pub fn lock_digest(lock: &ForeignLock) -> Result<String> {
    Ok(misa_plan::hash_bytes(&canonical_lock(lock)?))
}

pub fn digest_hex(digest: &str) -> Result<&str> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::new("E_LOCK", "digest", "only sha256 digests are supported"))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::new(
            "E_LOCK",
            "digest",
            "expected sha256 and 64 lowercase hexadecimal digits",
        ));
    }
    Ok(hex)
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(Error::new(
            "E_SCHEMA",
            "stratum",
            "use an ASCII identifier beginning with a lowercase letter (maximum 64 bytes)",
        ));
    }
    Ok(())
}

pub fn validate_source(source: &str) -> Result<()> {
    let (registry, repository) = source.split_once('/').ok_or_else(|| {
        Error::new(
            "E_LOCK",
            "source",
            "use a fully qualified registry/repository without a tag or digest",
        )
    })?;
    let label = |part: &str| {
        !part.is_empty()
            && part.as_bytes()[0].is_ascii_alphanumeric()
            && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if source.len() > 255
        || !registry.contains('.')
        || !registry.split('.').all(label)
        || !repository.split('/').all(|part| {
            !part.is_empty()
                && part.as_bytes()[0].is_ascii_alphanumeric()
                && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
    {
        return Err(Error::new(
            "E_LOCK",
            "source",
            "expected a lowercase DNS registry and repository; credentials, ports, tags and transport prefixes are not accepted in a lock",
        ));
    }
    Ok(())
}

pub fn validate_lock(lock: &ForeignLock) -> Result<()> {
    if lock.schema_version != 1 {
        return Err(Error::new(
            "E_SCHEMA",
            "schemaVersion",
            "unsupported foreign-lock version",
        ));
    }
    if !matches!(lock.target_platform.as_str(), "linux/amd64" | "linux/arm64") {
        return Err(Error::new(
            "E_ABI",
            "targetPlatform",
            "this importer supports linux/amd64 and linux/arm64 without implicit variants",
        ));
    }
    if lock.strata.is_empty() || lock.strata.len() > 64 {
        return Err(Error::new(
            "E_SCHEMA",
            "strata",
            "a lock must contain between 1 and 64 strata",
        ));
    }
    for (name, image) in &lock.strata {
        validate_name(name)?;
        validate_source(&image.source)?;
        if image.image.media_type != OCI_MANIFEST {
            return Err(Error::new(
                "E_CAPABILITY",
                "image.mediaType",
                "only OCI v1 image manifests are supported; resolve an OCI image without converting its identity",
            ));
        }
        digest_hex(&image.image.digest)?;
        if image.image.size == 0 || image.image.size > misa_plan::MAX_INPUT_BYTES as u64 {
            return Err(Error::new(
                "E_LOCK",
                "image.size",
                "manifest size must be between 1 byte and 1 MiB",
            ));
        }
        if let Some(index) = &image.source_index {
            if !matches!(index.media_type.as_str(), OCI_INDEX | DOCKER_INDEX) {
                return Err(Error::new(
                    "E_CAPABILITY",
                    "sourceIndex.mediaType",
                    "unsupported image-index media type",
                ));
            }
            digest_hex(&index.digest)?;
            if index.size == 0 || index.size > misa_plan::MAX_INPUT_BYTES as u64 {
                return Err(Error::new(
                    "E_LOCK",
                    "sourceIndex.size",
                    "index size must be between 1 byte and 1 MiB",
                ));
            }
        }
        if !matches!(image.libc_family.as_str(), "glibc" | "musl") {
            return Err(Error::new(
                "E_ABI",
                "libcFamily",
                "declare glibc or musl; this field does not qualify an application's ABI",
            ));
        }
        let limits = &image.limits;
        if !(1..=512 * 1024 * 1024).contains(&limits.max_blob_bytes)
            || !(1..=2 * 1024 * 1024 * 1024).contains(&limits.max_expanded_bytes)
            || !(1..=limits.max_expanded_bytes).contains(&limits.max_file_bytes)
            || limits.max_file_bytes > 512 * 1024 * 1024
            || !(1..=200_000).contains(&limits.max_entries)
            || !(1..=4096).contains(&limits.max_path_bytes)
            || !(1..=256).contains(&limits.max_expansion_ratio)
            || !(1..=600).contains(&limits.timeout_seconds)
        {
            return Err(Error::new(
                "E_LOCK",
                "limits",
                "import limits exceed the supported bounded profile; reduce them before approval",
            ));
        }
        if image.image.size > limits.max_blob_bytes
            || image
                .source_index
                .as_ref()
                .is_some_and(|d| d.size > limits.max_blob_bytes)
        {
            return Err(Error::new(
                "E_LOCK",
                "limits.maxBlobBytes",
                "the locked descriptor exceeds its own byte limit",
            ));
        }
    }
    Ok(())
}
