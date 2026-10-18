use crate::{
    Error, Result,
    model::{ForeignLock, lock_digest, parse_record},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

const APPROVAL_VERSION: &str = "misa.approval/v1";
const PUBLIC_VERSION: &str = "misa.ed25519-public/v1";
const SECRET_VERSION: &str = "misa.ed25519-secret/v1";
const AUTHORITY: &str = "local-image-admission";
const SIGNING_DOMAIN: &str = "misa.local-image-admission/v1\n";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approval {
    pub schema_version: String,
    pub authority: String,
    pub lock_digest: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicKey {
    pub schema_version: String,
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretKey {
    schema_version: String,
    secret_seed: String,
}

impl SecretKey {
    pub(crate) fn sign_message(&self, message: &[u8]) -> Result<[u8; 64]> {
        if self.schema_version != SECRET_VERSION {
            return Err(Error::new(
                "E_TRUST",
                "secretKey",
                "unsupported secret-key record",
            ));
        }
        let signing = SigningKey::from_bytes(&fixed_hex(&self.secret_seed, "secretKey")?);
        Ok(signing.sign(message).to_bytes())
    }
}

/// Possession proves admission of this exact lock by the caller-supplied trust key.
/// The signer is the local operator, not an asserted upstream image publisher.
pub struct AuthorizedLock {
    lock: ForeignLock,
    approval: Approval,
    public_key: PublicKey,
}

impl AuthorizedLock {
    pub fn lock(&self) -> &ForeignLock {
        &self.lock
    }
    pub fn approval(&self) -> &Approval {
        &self.approval
    }
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn lock_digest(&self) -> &str {
        &self.approval.lock_digest
    }
}

fn fixed_hex<const N: usize>(text: &str, field: &str) -> Result<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::new(
            "E_TRUST",
            field,
            "invalid lowercase hexadecimal key or signature encoding",
        ));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes)
        .map_err(|_| Error::new("E_TRUST", field, "invalid key or signature encoding"))?;
    Ok(bytes)
}

fn verifying_key(key: &PublicKey) -> Result<VerifyingKey> {
    if key.schema_version != PUBLIC_VERSION {
        return Err(Error::new(
            "E_TRUST",
            "publicKey.schemaVersion",
            "unsupported public-key record",
        ));
    }
    let key = VerifyingKey::from_bytes(&fixed_hex(&key.public_key, "publicKey")?)
        .map_err(|_| Error::new("E_TRUST", "publicKey", "invalid Ed25519 verification key"))?;
    if key.is_weak() {
        return Err(Error::new(
            "E_TRUST",
            "publicKey",
            "weak Ed25519 keys are not accepted",
        ));
    }
    Ok(key)
}

pub fn key_id(key: &PublicKey) -> Result<String> {
    Ok(misa_plan::hash_bytes(verifying_key(key)?.as_bytes()))
}

pub fn parse_public_key(bytes: &[u8]) -> Result<PublicKey> {
    let key = parse_record(bytes, "publicKey")?;
    verifying_key(&key)?;
    Ok(key)
}

pub fn parse_secret_key(bytes: &[u8]) -> Result<SecretKey> {
    let key: SecretKey = parse_record(bytes, "secretKey")?;
    if key.schema_version != SECRET_VERSION {
        return Err(Error::new(
            "E_TRUST",
            "secretKey.schemaVersion",
            "unsupported secret-key record",
        ));
    }
    fixed_hex::<32>(&key.secret_seed, "secretKey")?;
    Ok(key)
}

pub fn parse_approval(bytes: &[u8]) -> Result<Approval> {
    let approval: Approval = parse_record(bytes, "approval")?;
    validate_approval(&approval)?;
    Ok(approval)
}

fn validate_approval(approval: &Approval) -> Result<()> {
    if approval.schema_version != APPROVAL_VERSION || approval.authority != AUTHORITY {
        return Err(Error::new(
            "E_TRUST",
            "approval.authority",
            "require a misa.approval/v1 local-image-admission approval; publisher signatures are a different authority",
        ));
    }
    crate::model::digest_hex(&approval.lock_digest)?;
    crate::model::digest_hex(&approval.key_id)?;
    fixed_hex::<64>(&approval.signature, "approval.signature")?;
    Ok(())
}

pub fn generate_keypair() -> Result<(SecretKey, PublicKey)> {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).map_err(|_| {
        Error::new(
            "E_TRUST",
            "keygen",
            "operating-system randomness unavailable; no key created",
        )
    })?;
    let signing = SigningKey::from_bytes(&seed);
    Ok((
        SecretKey {
            schema_version: SECRET_VERSION.into(),
            secret_seed: hex::encode(seed),
        },
        PublicKey {
            schema_version: PUBLIC_VERSION.into(),
            public_key: hex::encode(signing.verifying_key().as_bytes()),
        },
    ))
}

pub fn approve(lock: &ForeignLock, secret: &SecretKey) -> Result<Approval> {
    if secret.schema_version != SECRET_VERSION {
        return Err(Error::new(
            "E_TRUST",
            "secretKey",
            "unsupported secret-key record",
        ));
    }
    let signing = SigningKey::from_bytes(&fixed_hex(&secret.secret_seed, "secretKey")?);
    let digest = lock_digest(lock)?;
    let signature = signing.sign(format!("{SIGNING_DOMAIN}{digest}").as_bytes());
    Ok(Approval {
        schema_version: APPROVAL_VERSION.into(),
        authority: AUTHORITY.into(),
        lock_digest: digest,
        key_id: misa_plan::hash_bytes(signing.verifying_key().as_bytes()),
        signature: hex::encode(signature.to_bytes()),
    })
}

pub fn verify_approval(
    lock: ForeignLock,
    approval: Approval,
    public_key: PublicKey,
) -> Result<AuthorizedLock> {
    validate_approval(&approval)?;
    let verifying = verifying_key(&public_key)?;
    if misa_plan::hash_bytes(verifying.as_bytes()) != approval.key_id {
        return Err(Error::new(
            "E_TRUST",
            "approval.keyId",
            "approval was not made by the supplied trusted key; select the intended authority explicitly",
        ));
    }
    if lock_digest(&lock)? != approval.lock_digest {
        return Err(Error::new(
            "E_TRUST",
            "approval.lockDigest",
            "lock differs from the approved canonical bytes; review and reapprove it",
        ));
    }
    let signature = Signature::from_bytes(&fixed_hex(&approval.signature, "approval.signature")?);
    verifying
        .verify_strict(
            format!("{SIGNING_DOMAIN}{}", approval.lock_digest).as_bytes(),
            &signature,
        )
        .map_err(|_| {
            Error::new(
                "E_TRUST",
                "approval.signature",
                "local admission signature verification failed; do not import these bytes",
            )
        })?;
    Ok(AuthorizedLock {
        lock,
        approval,
        public_key,
    })
}
