//! Spawn bubblewrap, hold the payload before `exec`, attest the live sandbox,
//! release it, and relay its exit status.
//!
//! bubblewrap's `--block-fd` makes the sandbox init read one byte after all
//! mounts, namespaces and privilege drops are done and before it forks/execs the
//! payload. While it waits there this launcher reads `/proc/<pid>/` from outside:
//! fresh namespaces, `NoNewPrivs`, empty capability sets, and an exact mountinfo
//! match (root `ro,nosuid,nodev`, no leftover old root). Only then is the byte
//! written. Any failure kills bubblewrap, so the payload never runs unattested.
//! The caller must already have authenticated the root; the CLI path is
//! `crate::run`. No `Store` handle exists here, so no writer lock is held while
//! the payload lives.
use crate::{
    Error, Result,
    exec::{self, Isa, Libc},
    plan::Export,
    sandbox::{self, ResolvedGrant},
};
use serde_json::Value;
use std::{
    ffi::OsString,
    fs,
    io::{BufRead, BufReader, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{fs::MetadataExt, process::ExitStatusExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_arch = "x86_64")]
const SYS_READ: &str = "0";
#[cfg(target_arch = "aarch64")]
const SYS_READ: &str = "63";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("misa-exec supports x86_64 and aarch64 Linux only");

const SETUP_TIMEOUT: Duration = Duration::from_secs(20);

/// A verified root plus the declared export to run from it.
pub struct Job<'a> {
    pub bwrap: &'a Path,
    pub store: &'a Path,
    pub rootfs: &'a Path,
    pub export: &'a Export,
    pub user_args: &'a [OsString],
    pub isa: Isa,
    pub libc: Libc,
}

fn sandbox_error(field: &str, message: impl Into<String>) -> Error {
    Error::new("E_SANDBOX", field, message)
}

fn io_error(field: &str, error: impl std::fmt::Display) -> Error {
    Error::new("E_IO", field, format!("{field}: {error}"))
}

/// Qualify the execution chain, build the view, attest it, and run the payload.
/// Returns the payload's exit status (128+n if it died from signal n).
pub fn launch(job: &Job<'_>) -> Result<i32> {
    exec::resolve(job.rootfs, &job.export.program, job.isa, job.libc)?;
    sandbox::require_mount_points(job.rootfs)?;
    let grants = sandbox::resolve_grants(job.export, job.store, job.rootfs)?;
    let env = sandbox::environment(job.export, &grants)?;
    let root_device = sandbox::split_dev(
        fs::metadata(job.rootfs)
            .map_err(|e| io_error("rootfs", e))?
            .dev(),
    );

    let (status_reader, status_writer) = std::io::pipe().map_err(|e| io_error("pipe", e))?;
    let (block_reader, mut block_writer) = std::io::pipe().map_err(|e| io_error("pipe", e))?;
    // Only these two duplicates are inheritable; every other descriptor of this
    // process is close-on-exec and bubblewrap closes the rest.
    let status_child: OwnedFd = rustix::io::dup(&status_writer).map_err(|e| io_error("dup", e))?;
    let block_child: OwnedFd = rustix::io::dup(&block_reader).map_err(|e| io_error("dup", e))?;
    let block_fd = block_child.as_raw_fd();
    let args = sandbox::bwrap_args(&sandbox::Plan {
        rootfs: job.rootfs,
        export: job.export,
        user_args: job.user_args,
        grants: &grants,
        env: &env,
        status_fd: status_child.as_raw_fd(),
        block_fd,
    })?;
    let mut child = Command::new(job.bwrap)
        .args(&args)
        .env_clear()
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| sandbox_error("bwrap", format!("cannot start bubblewrap: {e}")))?;
    drop(status_child);
    drop(block_child);
    drop(status_writer);
    drop(block_reader);

    // Keep the status reader open until bubblewrap is reaped: closing it early
    // would turn bubblewrap's final status write into SIGPIPE.
    let mut status = BufReader::new(status_reader);
    if let Err(error) = attest(&mut status, &mut child, block_fd, root_device, &grants) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    if let Err(error) = block_writer.write_all(b"1") {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io_error("block-fd", error));
    }
    drop(block_writer);
    let exit = child.wait().map_err(|e| io_error("wait", e))?;
    drop(status);
    Ok(exit
        .code()
        .or_else(|| exit.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

fn attest(
    status: &mut impl BufRead,
    child: &mut Child,
    block_fd: i32,
    root_device: (u32, u32),
    grants: &[ResolvedGrant],
) -> Result<()> {
    let mut line = String::new();
    let read = status
        .read_line(&mut line)
        .map_err(|e| io_error("json-status", e))?;
    if read == 0 {
        let outcome = child
            .wait()
            .map(|status| status.to_string())
            .unwrap_or_else(|_| "unknown".into());
        return Err(sandbox_error(
            "bwrap",
            format!(
                "bubblewrap exited before the sandbox was ready ({outcome}); user namespaces or a grant may be unavailable, see its diagnostic above"
            ),
        ));
    }
    let pid = serde_json::from_str::<Value>(&line)
        .ok()
        .and_then(|value| value["child-pid"].as_u64())
        .ok_or_else(|| sandbox_error("json-status", "bubblewrap reported no child pid"))?;
    wait_until_blocked(pid, block_fd, child)?;
    check_isolation(pid)?;
    check_privileges(pid)?;
    let mountinfo = fs::read_to_string(format!("/proc/{pid}/mountinfo"))
        .map_err(|e| sandbox_error("mountinfo", format!("cannot read sandbox mounts: {e}")))?;
    sandbox::verify_mountinfo(&mountinfo, root_device, grants)
}

/// The sandbox init has finished setup exactly when it sits in `read(block_fd)`.
fn wait_until_blocked(pid: u64, block_fd: i32, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let wanted_fd = format!("0x{block_fd:x}");
    loop {
        if let Ok(Some(outcome)) = child.try_wait() {
            return Err(sandbox_error(
                "bwrap",
                format!(
                    "bubblewrap exited during sandbox setup ({outcome}); see its diagnostic above"
                ),
            ));
        }
        if let Ok(syscall) = fs::read_to_string(format!("/proc/{pid}/syscall")) {
            let mut fields = syscall.split_whitespace();
            if fields.next() == Some(SYS_READ) && fields.next() == Some(wanted_fd.as_str()) {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            return Err(sandbox_error(
                "bwrap",
                "the sandbox did not reach its pre-exec hold point in time",
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn check_isolation(pid: u64) -> Result<()> {
    for namespace in ["user", "ipc", "pid", "net", "mnt", "uts"] {
        let ours = fs::read_link(format!("/proc/self/ns/{namespace}")).map_err(|e| {
            sandbox_error(
                "namespace",
                format!("cannot read {namespace} namespace: {e}"),
            )
        })?;
        let theirs = fs::read_link(format!("/proc/{pid}/ns/{namespace}")).map_err(|e| {
            sandbox_error(
                "namespace",
                format!("cannot read sandbox {namespace} namespace: {e}"),
            )
        })?;
        if ours == theirs {
            return Err(sandbox_error(
                "namespace",
                format!("the sandbox shares this process's {namespace} namespace"),
            ));
        }
    }
    Ok(())
}

fn check_privileges(pid: u64) -> Result<()> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| sandbox_error("status", format!("cannot read sandbox status: {e}")))?;
    let value = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
            .map(str::trim)
    };
    let zero = |text: Option<&str>| text.is_some_and(|hex| hex.bytes().all(|b| b == b'0'));
    if value("NoNewPrivs") != Some("1") || !zero(value("CapEff")) || !zero(value("CapPrm")) {
        return Err(sandbox_error(
            "status",
            "the sandbox keeps privileges or lacks no_new_privs",
        ));
    }
    Ok(())
}
