//! Strict `misa.strata/v1` selection of one export and its declared root.
//!
//! Validation is `misa_plan::validate` (strict JSON, closed schema, semantic
//! rules). Selection adds only launcher-specific refusals: an export that names
//! no unique OCI root, a storage mode other than retain-all, required features
//! this launcher cannot provide, and anything that would need a GC broker.
use crate::{Error, Result};
use misa_plan::{Domain, MAX_INPUT_BYTES};
use serde_json::Value;
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantKind {
    File,
    Directory,
    SessionSocket,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub kind: GrantKind,
    pub source: String,
    pub target: String,
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Retiring,
    Revoked,
}

/// Plan-side publisher policy entry; public bytes live only in the pinned keyring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherKey {
    pub key_id: String,
    pub status: KeyStatus,
    pub valid_from: u64,
    pub valid_until: u64,
    pub revoked_not_before: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Export {
    pub id: String,
    pub name: String,
    pub program: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub grants: Vec<Grant>,
}

#[derive(Clone, Debug)]
pub struct Root {
    pub name: String,
    pub platform: String,
    pub libc_family: String,
    pub digest: String,
    pub source_lock_key: String,
    pub layout: String,
    pub compose_receipt_digest: String,
}

#[derive(Clone, Debug)]
pub struct Selection {
    pub plan_digest: String,
    pub export: Export,
    pub root: Root,
    /// Entries of `trust.imagePublishers[root.source_lock_key]`; empty is a refusal later.
    pub publisher_keys: Vec<PublisherKey>,
    pub floor_epoch: u64,
    pub foreign_lock_digest: String,
}

pub fn read_plan(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .map_err(|_| Error::new("E_IO", "plan", "cannot open the strata plan file"))?;
    if !file
        .metadata()
        .map_err(|_| Error::new("E_IO", "plan", "cannot inspect the strata plan file"))?
        .is_file()
    {
        return Err(Error::new(
            "E_IO",
            "plan",
            "the strata plan must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("E_IO", "plan", "cannot read the strata plan file"))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::new(
            "E_SCHEMA",
            "plan",
            "record exceeds the 1 MiB limit",
        ));
    }
    Ok(bytes)
}

fn field(value: &Value, key: &str, at: &str) -> Result<Value> {
    value.get(key).cloned().ok_or_else(|| {
        Error::new(
            "E_SCHEMA",
            format!("{at}/{key}"),
            "required field is missing",
        )
    })
}

fn text(value: &Value, key: &str, at: &str) -> Result<String> {
    field(value, key, at)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::new("E_SCHEMA", format!("{at}/{key}"), "expected a string"))
}

fn number(value: &Value, key: &str, at: &str) -> Result<u64> {
    field(value, key, at)?.as_u64().ok_or_else(|| {
        Error::new(
            "E_SCHEMA",
            format!("{at}/{key}"),
            "expected an unsigned integer",
        )
    })
}

fn list(value: &Value, key: &str, at: &str) -> Result<Vec<Value>> {
    field(value, key, at)?
        .as_array()
        .cloned()
        .ok_or_else(|| Error::new("E_SCHEMA", format!("{at}/{key}"), "expected an array"))
}

/// Validate `bytes` as strict `misa.strata/v1` and select `export_id`.
pub fn select(bytes: &[u8], export_id: &str) -> Result<Selection> {
    let record = misa_plan::validate(bytes, Some(Domain::Strata))?;
    let value = record.value();
    if text(
        &field(value, "foreignStorage", "")?,
        "mode",
        "/foreignStorage",
    )? != "retain-all"
    {
        return Err(Error::new(
            "E_CAPABILITY",
            "/foreignStorage/mode",
            "only retain-all storage is launchable; there is no per-launch root broker",
        ));
    }
    if !list(value, "requiredFeatures", "")?.is_empty() {
        return Err(Error::new(
            "E_CAPABILITY",
            "/requiredFeatures",
            "the launcher implements no optional features",
        ));
    }
    let exports = list(value, "exports", "")?;
    let export = exports
        .iter()
        .find(|candidate| candidate["id"] == export_id)
        .ok_or_else(|| {
            Error::new(
                "E_LOCK",
                "export",
                "the plan declares no export with this id; nothing else is launchable",
            )
        })?;
    let root_digest = text(export, "root", "/exports")?;
    let roots = list(value, "roots", "")?;
    let mut matching = roots.iter().filter(|root| root["digest"] == root_digest);
    let root = matching.next().ok_or_else(|| {
        Error::new(
            "E_LOCK",
            "/exports/root",
            "export references no declared sealed root",
        )
    })?;
    if matching.next().is_some() {
        return Err(Error::new(
            "E_LOCK",
            "/roots",
            "several declared roots share one manifest digest",
        ));
    }
    let sealed = field(root, "sealedPath", "/roots")?;
    if text(&sealed, "kind", "/roots/sealedPath")? != "oci" {
        return Err(Error::new(
            "E_CAPABILITY",
            "/roots/sealedPath/kind",
            "only imported OCI roots are launchable; Nix-store layouts are not a retained S1 root",
        ));
    }
    if text(root, "qualification", "/roots")? != "R1" {
        return Err(Error::new(
            "E_CAPABILITY",
            "/roots/qualification",
            "only R1 roots are launchable",
        ));
    }
    let root = Root {
        name: text(root, "name", "/roots")?,
        platform: text(root, "platform", "/roots")?,
        libc_family: text(root, "libcFamily", "/roots")?,
        digest: root_digest,
        source_lock_key: text(root, "sourceLockKey", "/roots")?,
        layout: text(&sealed, "layout", "/roots/sealedPath")?,
        compose_receipt_digest: text(root, "composeReceiptDigest", "/roots")?,
    };

    let declared: Vec<Value> = list(value, "hostGrants", "")?;
    let mut grants = Vec::new();
    for id in list(export, "grants", "/exports")? {
        let id = id
            .as_str()
            .ok_or_else(|| Error::new("E_SCHEMA", "/exports/grants", "expected grant ids"))?;
        let grant = declared
            .iter()
            .find(|grant| grant["id"] == id)
            .ok_or_else(|| {
                Error::new(
                    "E_SCHEMA",
                    "/exports/grants",
                    "export references an undeclared host grant",
                )
            })?;
        let kind = match text(grant, "kind", "/hostGrants")?.as_str() {
            "file" => GrantKind::File,
            "directory" => GrantKind::Directory,
            "session-socket" => GrantKind::SessionSocket,
            _ => {
                return Err(Error::new(
                    "E_SCHEMA",
                    "/hostGrants/kind",
                    "unknown grant kind",
                ));
            }
        };
        grants.push(Grant {
            id: id.to_owned(),
            kind,
            source: text(grant, "source", "/hostGrants")?,
            target: text(grant, "target", "/hostGrants")?,
            writable: field(grant, "writable", "/hostGrants")?
                .as_bool()
                .ok_or_else(|| {
                    Error::new("E_SCHEMA", "/hostGrants/writable", "expected a boolean")
                })?,
        });
    }

    let mut env = BTreeMap::new();
    let literal = field(export, "env", "/exports")?;
    for (name, entry) in literal
        .as_object()
        .ok_or_else(|| Error::new("E_SCHEMA", "/exports/env", "expected an environment object"))?
    {
        env.insert(
            name.clone(),
            entry
                .as_str()
                .ok_or_else(|| Error::new("E_SCHEMA", "/exports/env", "expected string values"))?
                .to_owned(),
        );
    }
    let mut argv = Vec::new();
    for entry in list(export, "argv", "/exports")? {
        argv.push(
            entry
                .as_str()
                .ok_or_else(|| Error::new("E_SCHEMA", "/exports/argv", "expected strings"))?
                .to_owned(),
        );
    }
    let export = Export {
        id: text(export, "id", "/exports")?,
        name: text(export, "name", "/exports")?,
        program: text(export, "program", "/exports")?,
        argv,
        env,
        grants,
    };

    let trust = field(value, "trust", "")?;
    let mut publisher_keys = Vec::new();
    let policy = field(&trust, "imagePublishers", "/trust")?;
    if let Some(entries) = policy.get(&root.source_lock_key) {
        for entry in entries.as_array().ok_or_else(|| {
            Error::new("E_SCHEMA", "/trust/imagePublishers", "expected key arrays")
        })? {
            let status = match text(entry, "status", "/trust/imagePublishers")?.as_str() {
                "active" => KeyStatus::Active,
                "retiring" => KeyStatus::Retiring,
                "revoked" => KeyStatus::Revoked,
                _ => {
                    return Err(Error::new(
                        "E_SCHEMA",
                        "/trust/imagePublishers/status",
                        "unknown publisher key status",
                    ));
                }
            };
            publisher_keys.push(PublisherKey {
                key_id: text(entry, "keyId", "/trust/imagePublishers")?,
                status,
                valid_from: number(entry, "validFrom", "/trust/imagePublishers")?,
                valid_until: number(entry, "validUntil", "/trust/imagePublishers")?,
                revoked_not_before: entry.get("revokedNotBefore").and_then(Value::as_u64),
            });
        }
    }
    let floor_epoch = number(
        &field(&trust, "time", "/trust")?,
        "floorEpoch",
        "/trust/time",
    )?;
    let foreign_lock_digest = text(&field(value, "inputs", "")?, "foreignLockDigest", "/inputs")?;
    Ok(Selection {
        plan_digest: record.digest().to_owned(),
        export,
        root,
        publisher_keys,
        floor_epoch,
        foreign_lock_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRATA: &str = include_str!("../../../fixtures/strata.json");

    fn mutate(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_str(STRATA).unwrap();
        edit(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn selects_the_declared_export_root_grants_and_publisher_policy() {
        let selection = select(STRATA.as_bytes(), "debian-hello").unwrap();
        assert_eq!(selection.export.program, "/usr/bin/printf");
        assert_eq!(selection.export.argv[0], "printf");
        assert_eq!(selection.export.env["LANG"], "C.UTF-8");
        assert_eq!(selection.export.grants.len(), 1);
        assert_eq!(selection.export.grants[0].kind, GrantKind::Directory);
        assert!(selection.export.grants[0].writable);
        assert_eq!(selection.root.source_lock_key, "debian");
        assert_eq!(selection.publisher_keys.len(), 1);
        assert_eq!(selection.publisher_keys[0].key_id, "synthetic-review");
        assert_eq!(selection.publisher_keys[0].status, KeyStatus::Active);
        assert_eq!(selection.floor_epoch, 1_767_225_600);
    }

    #[test]
    fn an_undeclared_export_is_never_launchable() {
        let error = select(STRATA.as_bytes(), "bash").unwrap_err();
        assert_eq!(error.code, "E_LOCK");
    }

    #[test]
    fn unknown_fields_and_duplicate_keys_fail_before_selection() {
        let unknown = mutate(|value| {
            value["exports"][0]["shell"] = Value::String("/bin/sh".into());
        });
        assert_eq!(
            select(&unknown, "debian-hello").unwrap_err().code,
            "E_SCHEMA"
        );
        let duplicate = br#"{"schemaVersion":"misa.strata/v1","schemaVersion":"misa.strata/v1"}"#;
        assert!(select(duplicate, "debian-hello").is_err());
    }

    #[test]
    fn other_authority_domains_are_not_strata_plans() {
        let plan = include_str!("../../../fixtures/plan.json");
        assert!(select(plan.as_bytes(), "debian-hello").is_err());
    }

    #[test]
    fn nix_store_roots_and_leased_gc_are_refused_not_emulated() {
        let store_root = mutate(|value| {
            value["roots"][0]["sealedPath"] = serde_json::json!({
                "kind": "store",
                "path": "/nix/store/00000000000000000000000000000000-root"
            });
        });
        assert_eq!(
            select(&store_root, "debian-hello").unwrap_err().code,
            "E_CAPABILITY"
        );
        let leased = mutate(|value| {
            value["foreignStorage"] = serde_json::json!({
                "mode": "leased-gc",
                "minRetainSeconds": "1",
                "brokerPolicyDigest":
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            });
        });
        assert!(select(&leased, "debian-hello").is_err());
    }

    #[test]
    fn a_root_without_publisher_policy_selects_no_keys() {
        let bytes = mutate(|value| {
            value["trust"]["imagePublishers"] = serde_json::json!({});
        });
        let selection = select(&bytes, "debian-hello").unwrap();
        assert!(selection.publisher_keys.is_empty());
    }
}
