//! Publisher authentication gate. A local admission signature (verified by
//! `binding`) names the operator who imported bytes; it is never publisher
//! identity. A launch proceeds only when a plan-declared publisher key that is
//! active/retiring and inside its window also verifies the retained publisher
//! statement against the externally pinned keyring.
use crate::{
    Error, Result, binding::Binding, plan::KeyStatus, plan::PublisherKey, plan::Selection,
};
use misa_image::{Store, publisher as statements};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// A root whose publisher statement verified under a plan-declared, in-window key.
#[derive(Debug)]
pub struct Authenticated {
    pub rootfs: PathBuf,
    pub key_id: String,
}

/// Plan-policy keys usable at `now`. Revoked keys are never usable here, expired
/// or not-yet-valid keys are not usable, and a clock below the plan's trusted
/// floor refuses everything: no window can be evaluated against a rolled-back clock.
pub fn eligible(keys: &[PublisherKey], floor_epoch: u64, now: u64) -> Result<Vec<&PublisherKey>> {
    if keys.is_empty() {
        return Err(Error::new(
            "E_TRUST",
            "trust.imagePublishers",
            "the plan declares no publisher key for this root; unauthenticated roots are not launchable",
        ));
    }
    if now < floor_epoch {
        return Err(Error::new(
            "E_TRUST",
            "trust.time.floorEpoch",
            "the clock is below the plan's trusted time floor; publisher windows cannot be evaluated",
        ));
    }
    let usable: Vec<_> = keys
        .iter()
        .filter(|key| {
            key.status != KeyStatus::Revoked && key.valid_from <= now && now < key.valid_until
        })
        .collect();
    if usable.is_empty() {
        return Err(Error::new(
            "E_TRUST",
            "trust.imagePublishers",
            "every declared publisher key is revoked, expired or not yet valid",
        ));
    }
    Ok(usable)
}

pub fn authenticate(
    bound: &Binding,
    selection: &Selection,
    keyring: &Path,
    now: u64,
) -> Result<Authenticated> {
    let usable = eligible(&selection.publisher_keys, selection.floor_epoch, now)?;
    let keyring = fs::canonicalize(keyring).map_err(|_| {
        Error::new(
            "E_TRUST",
            "publisherKeyring",
            "the pinned publisher keyring directory is missing; refusing to launch",
        )
    })?;
    if !fs::metadata(&keyring).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(Error::new(
            "E_TRUST",
            "publisherKeyring",
            "the pinned publisher keyring must be a directory",
        ));
    }
    let mut last = None;
    for key in usable {
        match verify_statement(bound, selection, key, &keyring, now) {
            Ok(rootfs) => {
                return Ok(Authenticated {
                    rootfs,
                    key_id: key.key_id.clone(),
                });
            }
            Err(error) => last = Some(error),
        }
    }
    Err(last.expect("eligible() never returns an empty key list"))
}

/// Agreement and statement verification for one plan-declared key.
///
/// The pinned keyring record must agree with the plan's policy entry (status,
/// window, rotation bound), then `Store::launch_root_at` re-verifies the retained
/// publisher proof (retained signature chain, pinned key identity and usability,
/// receipt binding, sealed tree) and returns the rootfs only on success. The
/// store lock is held only for this call; nothing keeps it open during the run.
fn verify_statement(
    bound: &Binding,
    selection: &Selection,
    key: &PublisherKey,
    keyring: &Path,
    now: u64,
) -> Result<PathBuf> {
    let pinned = statements::load_key_record(keyring, &key.key_id)?;
    let status = match key.status {
        KeyStatus::Active => "active",
        KeyStatus::Retiring => "retiring",
        KeyStatus::Revoked => "revoked",
    };
    if pinned.status != status
        || pinned.valid_from != key.valid_from
        || pinned.valid_until != key.valid_until
        || pinned.revoked_not_before != key.revoked_not_before
    {
        return Err(Error::new(
            "E_TRUST",
            "trust.imagePublishers",
            "the pinned keyring record disagrees with the plan's publisher policy for this key",
        ));
    }
    let store = Store::open(&bound.store)?;
    let root = store.launch_root_at(
        &selection.root.digest,
        &selection.root.source_lock_key,
        &key.key_id,
        keyring,
        now,
    )?;
    drop(store);
    let verified = fs::canonicalize(&root).map_err(|_| {
        Error::new(
            "E_STATE",
            "publisherVerification",
            "the publisher-verified root is not reachable",
        )
    })?;
    if verified != bound.rootfs {
        return Err(Error::new(
            "E_TRUST",
            "publisherVerification",
            "the publisher-verified root differs from the root bound to this export",
        ));
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, status: KeyStatus, from: u64, until: u64) -> PublisherKey {
        PublisherKey {
            key_id: id.into(),
            status,
            valid_from: from,
            valid_until: until,
            revoked_not_before: None,
        }
    }

    #[test]
    fn absent_policy_refuses_instead_of_accepting_any_key() {
        let error = eligible(&[], 0, 100).unwrap_err();
        assert_eq!(error.code, "E_TRUST");
    }

    #[test]
    fn revoked_expired_and_future_keys_are_never_usable() {
        let keys = [
            key("revoked", KeyStatus::Revoked, 0, 1000),
            key("expired", KeyStatus::Active, 0, 50),
            key("future", KeyStatus::Active, 500, 1000),
        ];
        assert_eq!(eligible(&keys, 0, 100).unwrap_err().code, "E_TRUST");
    }

    #[test]
    fn active_and_retiring_keys_inside_their_window_are_usable() {
        let keys = [
            key("old", KeyStatus::Retiring, 0, 200),
            key("new", KeyStatus::Active, 50, 1000),
            key("gone", KeyStatus::Revoked, 0, 1000),
        ];
        let usable = eligible(&keys, 10, 100).unwrap();
        assert_eq!(
            usable.iter().map(|k| k.key_id.as_str()).collect::<Vec<_>>(),
            ["old", "new"]
        );
        assert_eq!(
            eligible(&keys, 0, 200).unwrap().len(),
            1,
            "until is exclusive"
        );
    }

    #[test]
    fn a_clock_below_the_trusted_floor_refuses_every_key() {
        let keys = [key("new", KeyStatus::Active, 0, 1000)];
        assert_eq!(
            eligible(&keys, 600, 100).unwrap_err().field,
            "trust.time.floorEpoch"
        );
    }
}
