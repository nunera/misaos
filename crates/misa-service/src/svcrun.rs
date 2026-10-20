//! `misa-svcrun`: the launcher between an init adapter and every service (Chapter 13).
//!
//! It reads a `misa.svcrun/v1` spec, never a shell string; creates declared
//! directories while still root; gives the service a readiness pipe at its declared
//! descriptor `M`, relayed to the manager's descriptor `N` only once a newline arrives
//! (R1-R6); closes every other inherited descriptor; drops to the declared UID/GID with
//! no supplementary groups and `no_new_privs`; and execs, so the supervisor keeps
//! tracking the same PID.
use crate::spec::SvcrunSpec;
use misa_plan::{Error, Result};
use std::ffi::CString;
use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt, process::CommandExt};
use std::{fs, path::Path};

fn os(field: &str, call: &str) -> Error {
    Error::new(
        "E_STATE",
        field.to_owned(),
        format!("{call}: {}", std::io::Error::last_os_error()),
    )
}

fn check(field: &str, call: &str, rc: libc::c_int) -> Result<()> {
    if rc < 0 { Err(os(field, call)) } else { Ok(()) }
}

/// Create declared directories as the launching user (root) before privileges drop.
pub fn prepare_directories(spec: &SvcrunSpec) -> Result<()> {
    for (i, dir) in spec.directories.iter().enumerate() {
        let field = format!("/directories/{i}");
        let path = Path::new(&dir.path);
        fs::create_dir_all(path)
            .map_err(|e| Error::new("E_STATE", field.clone(), e.to_string()))?;
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::new("E_SCHEMA", field.clone(), "path contains NUL"))?;
        // SAFETY: c is a valid NUL-terminated path.
        check(&field, "lchown", unsafe {
            libc::lchown(c.as_ptr(), dir.uid, dir.gid)
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(dir.mode))
            .map_err(|e| Error::new("E_STATE", field, e.to_string()))?;
    }
    Ok(())
}

/// Lowest descriptor the relay's private copies use; declared descriptors are 3..=255.
const PRIVATE_FD: i32 = 256;

fn private_copy(fd: i32) -> Result<i32> {
    // SAFETY: duplicates a descriptor this process owns; the copy is close-on-exec.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, PRIVATE_FD) };
    if copy < 0 {
        return Err(os("/readinessFd", "fcntl(F_DUPFD_CLOEXEC)"));
    }
    // SAFETY: the original is no longer needed; only `copy` is used from here on.
    unsafe { libc::close(fd) };
    Ok(copy)
}

/// R2 relay process: forward one newline to the manager's descriptor once the service
/// has written a newline, ignoring any bytes before it. Dinit's `pipefd` treats any
/// write as readiness, so the service never holds the manager's descriptor itself.
fn relay(service_end: i32, manager: i32) -> ! {
    let mut buf = [0u8; 512];
    let status = loop {
        // SAFETY: reads into a local buffer of the stated length.
        let n = unsafe { libc::read(service_end, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            if buf[..n as usize].contains(&b'\n') {
                // SAFETY: writes one byte from a static buffer.
                let wrote = unsafe { libc::write(manager, b"\n".as_ptr().cast(), 1) };
                break if wrote == 1 { 0 } else { 1 };
            }
        } else if n == 0
            || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            break 1; // closed or failed before the newline: never report readiness
        }
    };
    // SAFETY: terminate the relay without running the launcher's destructors.
    unsafe { libc::_exit(status) }
}

/// Give the service a fresh pipe at its declared descriptor `m` and start a detached
/// relay (re-parented to the init) that holds the manager's descriptor `n`.
fn readiness_pipe(m: u32, n: u32) -> Result<()> {
    let manager = private_copy(n as i32)?;
    let mut ends = [0i32; 2];
    // SAFETY: pipe2 fills both ends; both are close-on-exec.
    check("/readinessFd", "pipe2", unsafe {
        libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC)
    })?;
    let (read_end, write_end) = (private_copy(ends[0])?, private_copy(ends[1])?);
    // SAFETY: this launcher is single-threaded, so fork is sound; the intermediate
    // child only forks the relay and exits, and is reaped immediately.
    unsafe {
        let child = libc::fork();
        if child < 0 {
            return Err(os("/readinessFd", "fork"));
        }
        if child == 0 {
            match libc::fork() {
                0 => {
                    libc::close(write_end);
                    let rc =
                        libc::syscall(libc::SYS_close_range, 0u32, (PRIVATE_FD - 1) as u32, 0u32);
                    if rc < 0 {
                        libc::_exit(1);
                    }
                    relay(read_end, manager)
                }
                pid => libc::_exit(if pid < 0 { 1 } else { 0 }),
            }
        }
        let mut status = 0;
        if libc::waitpid(child, &mut status, 0) != child || status != 0 {
            return Err(Error::new(
                "E_STATE",
                "/readinessFd",
                "could not start the readiness relay",
            ));
        }
        // dup2 clears FD_CLOEXEC on m, so only the service's end crosses exec.
        check("/readinessFd", "dup2", libc::dup2(write_end, m as i32))?;
        libc::close(read_end);
        libc::close(write_end);
        libc::close(manager);
    }
    Ok(())
}

/// R1/R2/R6: give the service a readiness pipe at its declared descriptor, relayed to
/// the manager's, and close everything else except stdio. Without readiness, every
/// descriptor above 2 is closed.
pub fn arrange_descriptors(spec: &SvcrunSpec, manager_fd: Option<u32>) -> Result<()> {
    let keep = match (spec.readiness_fd, manager_fd) {
        (Some(m), Some(n)) => {
            readiness_pipe(m, n)?;
            Some(m)
        }
        (None, None) => None,
        (Some(_), None) => {
            return Err(Error::new(
                "E_SCHEMA",
                "--ready-fd",
                "the spec declares descriptor readiness but the manager passed no descriptor",
            ));
        }
        (None, Some(_)) => {
            return Err(Error::new(
                "E_SCHEMA",
                "--ready-fd",
                "the manager passed a readiness descriptor the spec does not declare",
            ));
        }
    };
    let close = |first: u32, last: u32| -> Result<()> {
        if first > last {
            return Ok(());
        }
        // SAFETY: close_range only closes descriptors in [first, last].
        let rc = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) };
        if rc < 0 {
            Err(os("/fds", "close_range"))
        } else {
            Ok(())
        }
    };
    match keep {
        Some(m) => {
            close(3, m - 1)?;
            close(m + 1, u32::MAX)
        }
        None => close(3, u32::MAX),
    }
}

fn drop_privileges(spec: &SvcrunSpec) -> Result<()> {
    let (uid, gid) = (spec.identity.uid, spec.identity.gid);
    // SAFETY: plain credential syscalls on this single-threaded process.
    unsafe {
        check(
            "/identity",
            "setgroups",
            libc::setgroups(0, std::ptr::null()),
        )?;
        check("/identity/gid", "setresgid", libc::setresgid(gid, gid, gid))?;
        check("/identity/uid", "setresuid", libc::setresuid(uid, uid, uid))?;
        check(
            "/identity",
            "no_new_privs",
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
        )?;
        libc::umask(0o022);
    }
    Ok(())
}

fn reset_signals() -> Result<()> {
    // SAFETY: restore default dispositions the Rust runtime changed and an empty mask.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        check(
            "/signals",
            "sigprocmask",
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()),
        )?;
    }
    Ok(())
}

/// Never returns on success.
pub fn launch(spec: &SvcrunSpec, manager_fd: Option<u32>) -> Error {
    let prepared = prepare_directories(spec)
        .and_then(|()| arrange_descriptors(spec, manager_fd))
        .and_then(|()| reset_signals())
        .and_then(|()| drop_privileges(spec));
    if let Err(error) = prepared {
        return error;
    }
    let error = std::process::Command::new(&spec.command)
        .arg0(&spec.argv[0])
        .args(&spec.argv[1..])
        .env_clear()
        .envs(&spec.env)
        .current_dir(&spec.cwd)
        .exec();
    Error::new(
        "E_STATE",
        "/command",
        format!("exec {}: {error}", spec.command),
    )
}
