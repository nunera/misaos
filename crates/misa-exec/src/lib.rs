//! Unprivileged launch of one declared strata export from a retained root.
//!
//! `run` is the only wired entry point: strict plan validation, export-to-receipt
//! binding against an explicit caller-owned store, full re-verification of the
//! retained local admission evidence, OCI chain and sealed tree, publisher
//! authentication against an externally pinned keyring, then a bubblewrap view
//! whose mount flags are read back from the live sandbox before the payload may
//! exec. There is no host fallback and no arbitrary-command mode.
pub mod binding;
pub mod exec;
pub mod launch;
pub mod plan;
pub mod publisher;
pub mod sandbox;
pub mod tree;

pub use misa_plan::{Error, Result};

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Everything the operator names explicitly; nothing is discovered or defaulted.
#[derive(Clone, Debug)]
pub struct Request {
    pub plan: PathBuf,
    pub store: PathBuf,
    pub export: String,
    pub publisher_keyring: PathBuf,
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| {
            Error::new(
                "E_TRUST",
                "clock",
                "system clock precedes the Unix epoch; publisher windows cannot be evaluated",
            )
        })
}

/// Verify and launch. Returns the payload's exit status (128+n for signal n).
/// Every launcher failure is a typed error raised before the payload executes.
pub fn run(request: &Request, user_args: &[OsString]) -> Result<i32> {
    run_at(request, user_args, unix_now()?)
}

/// As [`run`] with an explicit trusted clock reading, for deterministic checks.
pub fn run_at(request: &Request, user_args: &[OsString], now: u64) -> Result<i32> {
    run_with_bwrap(request, user_args, now, &sandbox::find_bwrap()?)
}

/// As [`run_at`] with an explicit pinned bubblewrap binary.
pub fn run_with_bwrap(
    request: &Request,
    user_args: &[OsString],
    now: u64,
    bwrap: &Path,
) -> Result<i32> {
    let bytes = plan::read_plan(&request.plan)?;
    let selection = plan::select(&bytes, &request.export)?;
    let bound = binding::bind(&request.store, &selection)?;
    let authenticated =
        publisher::authenticate(&bound, &selection, &request.publisher_keyring, now)?;
    let isa = exec::Isa::from_platform(&selection.root.platform)?;
    let libc = exec::Libc::from_family(&selection.root.libc_family)?;
    launch::launch(&launch::Job {
        bwrap,
        store: &bound.store,
        rootfs: &authenticated.rootfs,
        export: &selection.export,
        user_args,
        isa,
        libc,
    })
}
