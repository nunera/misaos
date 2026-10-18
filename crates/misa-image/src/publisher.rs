//! Independent image-publisher authentication, distinct from local operator admission.
//!
//! A publisher statement is an Ed25519 signature over one repository, one selected
//! OCI manifest digest, one platform and one ASCII key alias. The verification key is
//! never taken from the statement or the store: callers pass an externally pinned,
//! read-only keyring directory of `<keyId>.json` public-key records. There is no trust
//! on first use and no default publisher.
use crate::model::{self, parse_record};
use crate::{Error, Result, store, trust};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub const STATEMENT_VERSION: &str = "misa.publisher/v1";
pub const KEY_VERSION: &str = "misa.publisher-key/v1";
pub const PROOF_VERSION: &str = "misa.publisher-proof/v1";
const AUTHORITY: &str = "image-publisher";
// Different from the local-admission domain: a local approval signature can never
// verify as a publisher statement, whatever key signed it.
const SIGNING_DOMAIN: &str = "misa.image-publisher/v1\n";
const KEY_RECORD_LIMIT: u64 = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublisherStatement {
    pub schema_version: String,
    pub authority: String,
    /// Registry/repository exactly as in the locked source, without tag or digest.
    pub source: String,
    pub manifest_digest: String,
    pub platform: String,
    pub key_id: String,
    pub signature: String,
}

/// Public record in the external keyring. `key_id` is an ASCII alias (the same
/// `AsciiId` a `misa.strata/v1` publisher policy uses), not a key hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublisherKey {
    pub schema_version: String,
    pub key_id: String,
    pub alg: String,
    pub public_key: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_not_before: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successor_of: Option<String>,
}

/// Immutable evidence persisted in the caller-owned store by `Store::qualify_publisher`.
/// It retains the pinned public key and signed statement digest, never the policy
/// state (status/window), which is always re-read from the external keyring.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublisherProof {
    pub schema_version: String,
    pub name: String,
    pub source: String,
    pub manifest_digest: String,
    pub platform: String,
    pub key_id: String,
    pub public_key: String,
    pub key_fingerprint: String,
    pub statement_digest: String,
}

/// A statement whose signature, key identity and usability were verified against a
/// keyring. Construction stays in this module so callers cannot manufacture it.
#[derive(Debug)]
pub struct VerifiedStatement {
    statement: PublisherStatement,
    key: PublisherKey,
}

impl VerifiedStatement {
    pub fn statement(&self) -> &PublisherStatement {
        &self.statement
    }
    pub fn key(&self) -> &PublisherKey {
        &self.key
    }
}

fn trust_error(field: &str, message: &str) -> Error {
    Error::new("E_TRUST", field, message)
}

fn fixed_hex<const N: usize>(text: &str, field: &str) -> Result<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(trust_error(
            field,
            "invalid lowercase hexadecimal key or signature encoding",
        ));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes)
        .map_err(|_| trust_error(field, "invalid key or signature encoding"))?;
    Ok(bytes)
}

/// Key aliases use the plan's `AsciiId` syntax: `^[a-z][a-z0-9.-]*$`, at most 64 bytes.
/// A `sha256:` fingerprint is intentionally not a valid key identity.
pub fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id.as_bytes()[0].is_ascii_lowercase()
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(trust_error(
            "keyId",
            "publisher key ids are ASCII aliases beginning with a lowercase letter (maximum 64 bytes)",
        ));
    }
    Ok(())
}

fn validate_platform(platform: &str) -> Result<()> {
    if !matches!(platform, "linux/amd64" | "linux/arm64") {
        return Err(Error::new(
            "E_ABI",
            "platform",
            "publisher statements cover linux/amd64 and linux/arm64 only",
        ));
    }
    Ok(())
}

/// Validates a raw Ed25519 verification key and returns its 32 bytes.
pub fn decode_public_key(public_key: &str) -> Result<[u8; 32]> {
    let bytes = fixed_hex::<32>(public_key, "publicKey")?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| trust_error("publicKey", "invalid Ed25519 verification key"))?;
    if key.is_weak() {
        return Err(trust_error(
            "publicKey",
            "weak Ed25519 keys are not accepted",
        ));
    }
    Ok(bytes)
}

/// Diagnostic identity of the raw key bytes. It is never a trust anchor and never
/// replaces the externally pinned alias-to-key binding.
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    misa_plan::hash_bytes(public_key)
}

fn validate_statement(statement: &PublisherStatement) -> Result<()> {
    if statement.schema_version != STATEMENT_VERSION || statement.authority != AUTHORITY {
        return Err(trust_error(
            "statement.authority",
            "require a misa.publisher/v1 image-publisher statement; local admission approvals are a different authority",
        ));
    }
    model::validate_source(&statement.source)?;
    model::digest_hex(&statement.manifest_digest)?;
    validate_platform(&statement.platform)?;
    validate_key_id(&statement.key_id)?;
    fixed_hex::<64>(&statement.signature, "statement.signature")?;
    Ok(())
}

pub fn parse_statement(bytes: &[u8]) -> Result<PublisherStatement> {
    let statement: PublisherStatement = parse_record(bytes, "statement")?;
    validate_statement(&statement)?;
    Ok(statement)
}

pub fn parse_key_record(bytes: &[u8]) -> Result<PublisherKey> {
    let key: PublisherKey = parse_record(bytes, "publisherKey")?;
    if key.schema_version != KEY_VERSION || key.alg != "ed25519" {
        return Err(trust_error(
            "publisherKey.schemaVersion",
            "unsupported publisher-key record or algorithm",
        ));
    }
    validate_key_id(&key.key_id)?;
    decode_public_key(&key.public_key)?;
    if !matches!(key.status.as_str(), "active" | "retiring" | "revoked") {
        return Err(trust_error(
            "publisherKey.status",
            "status must be active, retiring or revoked",
        ));
    }
    if key.valid_from >= key.valid_until {
        return Err(trust_error(
            "publisherKey.validUntil",
            "publisher validity interval must have positive duration",
        ));
    }
    if let Some(predecessor) = &key.successor_of {
        validate_key_id(predecessor)?;
        if predecessor == &key.key_id {
            return Err(trust_error(
                "publisherKey.successorOf",
                "successor must reference a distinct key",
            ));
        }
    }
    Ok(key)
}

pub fn key_record_bytes(key: &PublisherKey) -> Result<Vec<u8>> {
    serde_jcs::to_vec(key)
        .map_err(|_| Error::new("E_SCHEMA", "publisherKey", "cannot canonicalize key record"))
}

/// Builds a keyring record for a raw public key under an explicit alias.
pub fn key_record(
    key_id: &str,
    public: &trust::PublicKey,
    valid_from: u64,
    valid_until: u64,
    status: &str,
) -> Result<PublisherKey> {
    let key = PublisherKey {
        schema_version: KEY_VERSION.into(),
        key_id: key_id.into(),
        alg: "ed25519".into(),
        public_key: public.public_key.clone(),
        valid_from,
        valid_until,
        status: status.into(),
        revoked_not_before: None,
        successor_of: None,
    };
    parse_key_record(&key_record_bytes(&key)?)?;
    Ok(key)
}

fn signed_message(statement: &PublisherStatement) -> Result<Vec<u8>> {
    let body = serde_jcs::to_vec(&json!({
        "authority": statement.authority,
        "keyId": statement.key_id,
        "manifestDigest": statement.manifest_digest,
        "platform": statement.platform,
        "source": statement.source,
    }))
    .map_err(|_| Error::new("E_SCHEMA", "statement", "cannot canonicalize statement"))?;
    let mut message = SIGNING_DOMAIN.as_bytes().to_vec();
    message.extend(body);
    Ok(message)
}

pub fn statement_digest(statement: &PublisherStatement) -> Result<String> {
    serde_jcs::to_vec(statement)
        .map(|bytes| misa_plan::hash_bytes(&bytes))
        .map_err(|_| Error::new("E_SCHEMA", "statement", "cannot canonicalize statement"))
}

/// Produces a publisher statement. The alias is chosen by the publisher/keyring owner;
/// it is not derived from the key.
pub fn sign_statement(
    source: &str,
    manifest_digest: &str,
    platform: &str,
    key_id: &str,
    secret: &trust::SecretKey,
) -> Result<PublisherStatement> {
    let mut statement = PublisherStatement {
        schema_version: STATEMENT_VERSION.into(),
        authority: AUTHORITY.into(),
        source: source.into(),
        manifest_digest: manifest_digest.into(),
        platform: platform.into(),
        key_id: key_id.into(),
        signature: "0".repeat(128),
    };
    validate_statement(&statement)?;
    statement.signature = hex::encode(secret.sign_message(&signed_message(&statement)?)?);
    Ok(statement)
}

/// Verifies the signature of an already syntactically valid statement under raw key bytes.
pub fn verify_signature(statement: &PublisherStatement, public_key: &[u8; 32]) -> Result<()> {
    validate_statement(statement)?;
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| trust_error("publicKey", "invalid Ed25519 verification key"))?;
    if key.is_weak() {
        return Err(trust_error(
            "publicKey",
            "weak Ed25519 keys are not accepted",
        ));
    }
    let signature = Signature::from_bytes(&fixed_hex(&statement.signature, "statement.signature")?);
    key.verify_strict(&signed_message(statement)?, &signature)
        .map_err(|_| {
            trust_error(
                "statement.signature",
                "publisher signature verification failed; do not launch these bytes",
            )
        })
}

/// A key record is usable at `now` only when it is not revoked and inside its window.
pub fn check_usable(key: &PublisherKey, now_unix_seconds: u64) -> Result<()> {
    if key.status == "revoked" {
        return Err(trust_error(
            "publisherKey.status",
            "publisher key is revoked; no launch is permitted under it",
        ));
    }
    if now_unix_seconds < key.valid_from {
        return Err(trust_error(
            "publisherKey.validFrom",
            "publisher key is not yet valid",
        ));
    }
    if now_unix_seconds >= key.valid_until {
        return Err(trust_error(
            "publisherKey.validUntil",
            "publisher key has expired",
        ));
    }
    Ok(())
}

fn external_read_only(metadata: &std::fs::Metadata, field: &str) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    if (metadata.uid() != 0 && metadata.uid() != uid) || metadata.mode() & 0o222 != 0 {
        return Err(trust_error(
            field,
            "keyring must be a read-only directory and records owned by root or the caller",
        ));
    }
    Ok(())
}

/// Loads `<keyring>/<keyId>.json` through directory-relative, symlink-free opens.
/// The filename is only a lookup; the closed body's keyId must equal the request.
pub fn load_key_record(keyring: &Path, key_id: &str) -> Result<PublisherKey> {
    validate_key_id(key_id)?;
    let directory = store::open_directory(keyring)
        .map_err(|_| trust_error("keyring", "pinned publisher keyring is unavailable"))?;
    external_read_only(
        &directory
            .metadata()
            .map_err(|_| trust_error("keyring", "cannot inspect pinned keyring"))?,
        "keyring",
    )?;
    let file = store::confined_file(&directory, Path::new(&format!("{key_id}.json")))
        .map_err(|_| trust_error("keyring", "publisher key is not pinned in the keyring"))?;
    external_read_only(
        &file
            .metadata()
            .map_err(|_| trust_error("keyring", "cannot inspect keyring record"))?,
        "keyring.record",
    )?;
    let record = parse_key_record(&store::read_handle(
        file,
        KEY_RECORD_LIMIT,
        "keyring.record",
    )?)?;
    if record.key_id != key_id {
        return Err(trust_error(
            "publisherKey.keyId",
            "keyring record identity differs from the requested publisher key",
        ));
    }
    Ok(record)
}

/// Verifies a statement against the externally pinned key for its own alias.
/// `now_unix_seconds` is explicit so verification is deterministic and testable.
pub fn verify_statement(
    statement: PublisherStatement,
    keyring: &Path,
    now_unix_seconds: u64,
) -> Result<VerifiedStatement> {
    validate_statement(&statement)?;
    let key = load_key_record(keyring, &statement.key_id)?;
    check_usable(&key, now_unix_seconds)?;
    verify_signature(&statement, &decode_public_key(&key.public_key)?)?;
    Ok(VerifiedStatement { statement, key })
}

pub(crate) fn validate_proof(proof: &PublisherProof) -> Result<()> {
    if proof.schema_version != PROOF_VERSION {
        return Err(trust_error(
            "proof.schemaVersion",
            "unsupported publisher proof",
        ));
    }
    model::validate_name(&proof.name)?;
    model::validate_source(&proof.source)?;
    model::digest_hex(&proof.manifest_digest)?;
    validate_platform(&proof.platform)?;
    validate_key_id(&proof.key_id)?;
    decode_public_key(&proof.public_key)?;
    model::digest_hex(&proof.key_fingerprint)?;
    model::digest_hex(&proof.statement_digest)?;
    Ok(())
}

/// Offline consistency of retained evidence: proof fields, the signed statement and its
/// signature under the retained key. Returns the retained key bytes.
pub(crate) fn check_proof(
    proof: &PublisherProof,
    statement: &PublisherStatement,
) -> Result<[u8; 32]> {
    validate_proof(proof)?;
    validate_statement(statement)?;
    let key = decode_public_key(&proof.public_key)?;
    if statement.source != proof.source
        || statement.manifest_digest != proof.manifest_digest
        || statement.platform != proof.platform
        || statement.key_id != proof.key_id
        || statement_digest(statement)? != proof.statement_digest
        || fingerprint(&key) != proof.key_fingerprint
    {
        return Err(trust_error(
            "proof",
            "retained publisher proof disagrees with its signed statement",
        ));
    }
    verify_signature(statement, &key)?;
    Ok(key)
}
