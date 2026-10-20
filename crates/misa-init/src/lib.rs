//! `misa-handoff`: the target of a borrowed stage 1's `switch_root`.
//!
//! It verifies the selected generation against the mounted root, records
//! `/run/misa/handoff.json`, points the adapter's stable paths at the generation and
//! execs the generation's init, keeping PID 1. On any failure it reports a typed
//! error on the console and halts: an unverified init never runs.
pub mod cmdline;
pub mod elf;
pub mod identity;
pub mod verify;

use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffRecord<'a> {
    pub schema_version: &'static str,
    pub generation: &'a str,
    pub plan: &'a str,
    pub top_level: &'a str,
    pub stage1: &'static str,
    /// V5 needs a build ID embedded by a Misa-owned initrd; a borrowed stage 1 has none.
    pub initrd_build_id_check: &'static str,
    pub root: RootRecord<'a>,
    pub unlock_method: &'a str,
    pub cmdline_sha256: &'a str,
    pub init: InitRecord<'a>,
    pub journal: &'a str,
    pub checks: &'a [&'static str],
    pub monotonic_ns: Monotonic,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootRecord<'a> {
    pub selector: String,
    pub device: Option<&'a str>,
    pub verified_by: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitRecord<'a> {
    pub path: &'a str,
    pub sha256: &'a str,
    pub adapter_id: &'a str,
    pub adapter_build_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Monotonic {
    pub start: u64,
    pub verified: u64,
}

pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// `uname -m` and `uname -r` of the running kernel.
pub fn machine() -> verify::Machine {
    // SAFETY: utsname is plain data filled by the kernel.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut uts) };
    let field = |f: &[libc::c_char]| {
        // SAFETY: the kernel NUL-terminates utsname fields.
        unsafe { std::ffi::CStr::from_ptr(f.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    verify::Machine {
        arch: field(&uts.machine),
        release: field(&uts.release),
    }
}
