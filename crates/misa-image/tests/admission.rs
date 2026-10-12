use ed25519_dalek::SigningKey;
use misa_image::{Descriptor, ForeignLock, Limits, LockedImage, model, trust};
use serde_json::json;
use std::collections::BTreeMap;

fn candidate() -> ForeignLock {
    ForeignLock {
        schema_version: 1,
        target_platform: "linux/amd64".into(),
        strata: BTreeMap::from([(
            "debian".into(),
            LockedImage {
                source: "registry.example.invalid/library/debian".into(),
                image: Descriptor {
                    media_type: model::OCI_MANIFEST.into(),
                    digest: misa_plan::hash_bytes(b"test manifest identity"),
                    size: 128,
                },
                source_index: None,
                libc_family: "glibc".into(),
                limits: Limits::default(),
            },
        )]),
    }
}

fn key(seed: u8) -> (trust::SecretKey, trust::PublicKey) {
    let bytes = [seed; 32];
    let secret = trust::parse_secret_key(
        &serde_json::to_vec(&json!({
            "schemaVersion":"misa.ed25519-secret/v1", "secretSeed":hex::encode(bytes)
        }))
        .unwrap(),
    )
    .unwrap();
    let public = trust::PublicKey {
        schema_version: "misa.ed25519-public/v1".into(),
        public_key: hex::encode(SigningKey::from_bytes(&bytes).verifying_key().as_bytes()),
    };
    (secret, public)
}

#[test]
fn signature_binds_every_admission_relevant_lock_field() {
    let lock = candidate();
    let (secret, public) = key(7);
    let approval = trust::approve(&lock, &secret).unwrap();
    let authorized =
        trust::verify_approval(lock.clone(), approval.clone(), public.clone()).unwrap();
    assert_eq!(authorized.lock_digest(), model::lock_digest(&lock).unwrap());
    let mutations: [fn(&mut ForeignLock); 6] = [
        |lock| lock.target_platform = "linux/arm64".into(),
        |lock| {
            lock.strata.get_mut("debian").unwrap().source =
                "other.example.invalid/library/debian".into()
        },
        |lock| {
            lock.strata.get_mut("debian").unwrap().image.digest =
                misa_plan::hash_bytes(b"substituted manifest")
        },
        |lock| lock.strata.get_mut("debian").unwrap().image.size += 1,
        |lock| lock.strata.get_mut("debian").unwrap().libc_family = "musl".into(),
        |lock| lock.strata.get_mut("debian").unwrap().limits.max_entries -= 1,
    ];
    for mutate in mutations {
        let mut changed = lock.clone();
        mutate(&mut changed);
        let error = trust::verify_approval(changed, approval.clone(), public.clone())
            .err()
            .unwrap();
        assert_eq!(error.code, "E_TRUST");
        assert_eq!(error.field, "approval.lockDigest");
    }
}

#[test]
fn wrong_authority_key_signature_and_domain_fail_closed() {
    let lock = candidate();
    let (secret, public) = key(9);
    let approval = trust::approve(&lock, &secret).unwrap();
    let (_, other_public) = key(10);
    assert_eq!(
        trust::verify_approval(lock.clone(), approval.clone(), other_public)
            .err()
            .unwrap()
            .field,
        "approval.keyId"
    );
    let mut forged = approval.clone();
    forged.signature.replace_range(
        0..2,
        if &forged.signature[..2] == "00" {
            "01"
        } else {
            "00"
        },
    );
    assert_eq!(
        trust::verify_approval(lock.clone(), forged, public.clone())
            .err()
            .unwrap()
            .code,
        "E_TRUST"
    );
    let mut relabeled = approval;
    relabeled.authority = "image-publisher".into();
    assert_eq!(
        trust::verify_approval(lock, relabeled, public)
            .err()
            .unwrap()
            .field,
        "approval.authority"
    );
}

#[test]
fn foreign_lock_wire_rejects_authority_smuggling_and_ambiguous_numbers() {
    let canonical = model::canonical_lock(&candidate()).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    for (field, replacement) in [("sourceIndex", json!(null)), ("unknownPolicy", json!(true))] {
        let mut changed = original.clone();
        changed["strata"]["debian"][field] = replacement;
        assert_eq!(
            model::parse_lock(&serde_json::to_vec(&changed).unwrap())
                .unwrap_err()
                .code,
            "E_SCHEMA"
        );
    }
    for size in [json!(128), json!("0128"), json!("-1"), json!("1048577")] {
        let mut changed = original.clone();
        changed["strata"]["debian"]["image"]["size"] = size;
        assert_eq!(
            model::parse_lock(&serde_json::to_vec(&changed).unwrap())
                .unwrap_err()
                .code,
            "E_SCHEMA"
        );
    }
    let duplicate = String::from_utf8(canonical).unwrap().replacen(
        "\"schemaVersion\":1",
        "\"schemaVersion\":1,\"schemaVersion\":1",
        1,
    );
    assert_eq!(
        model::parse_lock(duplicate.as_bytes()).unwrap_err().code,
        "E_SCHEMA"
    );
}

#[test]
fn byte_limit_schema_accepts_interior_values_and_rejects_overflow() {
    let mut lock = candidate();
    let image = lock.strata.get_mut("debian").unwrap();
    image.limits.max_blob_bytes = 123_456_789;
    image.limits.max_file_bytes = 100_000_001;
    image.limits.max_expanded_bytes = 1_001_234_567;
    let parsed = model::parse_lock(&model::canonical_lock(&lock).unwrap()).unwrap();
    assert_eq!(parsed.strata["debian"].limits.max_blob_bytes, 123_456_789);
    let mut wire = serde_json::to_value(lock).unwrap();
    wire["strata"]["debian"]["limits"]["maxExpandedBytes"] = json!("2147483649");
    assert_eq!(
        model::parse_lock(&serde_json::to_vec(&wire).unwrap())
            .unwrap_err()
            .code,
        "E_SCHEMA"
    );
}

#[test]
fn signature_is_independent_of_json_property_order_but_not_values() {
    let lock = candidate();
    let pretty = serde_json::to_vec_pretty(&lock).unwrap();
    let parsed = model::parse_lock(&pretty).unwrap();
    let (secret, public) = key(13);
    let approval = trust::approve(&lock, &secret).unwrap();
    assert_eq!(
        trust::verify_approval(parsed, approval.clone(), public)
            .unwrap()
            .lock_digest(),
        approval.lock_digest
    );
}
