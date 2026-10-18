//! Refusals that need no external tools: the explicit store is validated and the
//! plan's claims are never taken on trust. Positive launches are in `launch.rs`.
use misa_exec::{binding, plan};
use misa_image::Store;
use serde_json::Value;
use std::{fs, os::unix::fs::PermissionsExt, os::unix::fs::symlink, path::Path};

const STRATA: &str = include_str!("../../../fixtures/strata.json");

fn selection(layout: &Path) -> plan::Selection {
    let mut value: Value = serde_json::from_str(STRATA).unwrap();
    value["roots"][0]["sealedPath"]["layout"] = layout.to_str().unwrap().into();
    plan::select(&serde_json::to_vec(&value).unwrap(), "debian-hello").unwrap()
}

fn unprivileged() -> bool {
    if rustix::process::geteuid().as_raw() == 0 {
        eprintln!("binding test skipped: stores intentionally refuse UID 0");
        return false;
    }
    true
}

fn code(result: misa_exec::Result<binding::Binding>) -> &'static str {
    result.expect_err("binding must fail").code
}

#[test]
fn a_missing_or_loosely_permissioned_store_is_refused() {
    if !unprivileged() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store");
    let wanted = selection(&store.join("oci"));
    assert_eq!(code(binding::bind(&store, &wanted)), "E_IO");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(code(binding::bind(&store, &wanted)), "E_PATH_OWNER");
}

#[test]
fn a_symlinked_store_path_is_not_followed() {
    if !unprivileged() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real");
    drop(Store::open(&real).unwrap());
    let link = temp.path().join("link");
    symlink(&real, &link).unwrap();
    let wanted = selection(&real.join("oci"));
    assert_eq!(code(binding::bind(&link, &wanted)), "E_PATH_OWNER");
    assert_eq!(
        code(binding::bind(&link.join("../real"), &wanted)),
        "E_PATH_OWNER",
        "parent traversal is not normalized away"
    );
}

#[test]
fn plan_claims_without_a_retained_receipt_are_forged() {
    if !unprivileged() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store");
    drop(Store::open(&store).unwrap());
    // The synthetic fixture's layout path is not this store's retained layout.
    let foreign = plan::select(STRATA.as_bytes(), "debian-hello").unwrap();
    assert_eq!(code(binding::bind(&store, &foreign)), "E_LOCK");
    // Matching layout, but no receipt exists for the declared digests.
    let wanted = selection(&fs::canonicalize(&store).unwrap().join("oci"));
    let error = binding::bind(&store, &wanted).unwrap_err();
    assert_eq!(error.code, "E_LOCK");
    assert_eq!(error.field, "roots.composeReceiptDigest");
}
