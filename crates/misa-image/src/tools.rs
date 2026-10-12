use crate::{Error, Result};
use std::{
    env,
    io::{self, Read},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Tools {
    pub skopeo: PathBuf,
    pub umoci: PathBuf,
    pub bwrap: PathBuf,
}

impl Tools {
    /// Packaged wrappers supply exact paths; cargo users enter the pinned dev shell.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            skopeo: find_tool("MISA_SKOPEO", "skopeo")?,
            umoci: find_tool("MISA_UMOCI", "umoci")?,
            bwrap: find_tool("MISA_BWRAP", "bwrap")?,
        })
    }
}

fn find_tool(variable: &str, name: &str) -> Result<PathBuf> {
    let candidate = env::var_os(variable)
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("PATH").and_then(|paths| {
                env::split_paths(&paths)
                    .map(|directory| directory.join(name))
                    .find(|path| path.is_file())
            })
        })
        .ok_or_else(|| {
            Error::new(
                "E_CAPABILITY",
                name,
                "pinned image tools unavailable; use the packaged misa binary or nix develop",
            )
        })?;
    let resolved = candidate
        .canonicalize()
        .map_err(|_| Error::new("E_CAPABILITY", name, "cannot resolve required image tool"))?;
    if !resolved.starts_with("/nix/store") || !resolved.is_file() {
        return Err(Error::new(
            "E_CAPABILITY",
            name,
            "image tools must come from the pinned Nix environment, not an ambient host binary",
        ));
    }
    Ok(resolved)
}

fn read_available(
    reader: &mut impl Read,
    bytes: &mut Vec<u8>,
    maximum: usize,
    name: &str,
) -> Result<bool> {
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if count > maximum.saturating_sub(bytes.len()) {
                    return Err(Error::new(
                        "E_BUILD",
                        name,
                        "image tool exceeded its bounded output allowance",
                    ));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::new("E_IO", name, "cannot read image tool output")),
        }
    }
}

fn terminate(child: &mut Child) {
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// No shell, inherited stdin, unbounded output buffer, or unbounded child lifetime.
pub fn run_capture(command: &mut Command, timeout: Duration, max_stdout: usize) -> Result<Vec<u8>> {
    let name = Path::new(command.get_program())
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("image-tool")
        .to_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| Error::new("E_BUILD", &name, "cannot start pinned image tool"))?;
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let flags = rustix::fs::OFlags::NONBLOCK;
    if rustix::fs::fcntl_setfl(&stdout_pipe, flags).is_err()
        || rustix::fs::fcntl_setfl(&stderr_pipe, flags).is_err()
    {
        terminate(&mut child);
        return Err(Error::new(
            "E_IO",
            &name,
            "cannot make image tool output nonblocking",
        ));
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let started = Instant::now();
    let status = (|| {
        let mut status = None;
        let mut stdout_closed = false;
        let mut stderr_closed = false;
        loop {
            if started.elapsed() > timeout {
                return Err(Error::new(
                    "E_BUILD",
                    &name,
                    "image tool exceeded the approved wall-time limit; private staging is not an admitted root",
                ));
            }
            if !stdout_closed {
                stdout_closed = read_available(&mut stdout_pipe, &mut stdout, max_stdout, &name)?;
            }
            if !stderr_closed {
                stderr_closed = read_available(&mut stderr_pipe, &mut stderr, 8192, &name)?;
            }
            if status.is_none() {
                status = child.try_wait().map_err(|_| {
                    Error::new("E_BUILD", &name, "cannot observe image tool completion")
                })?;
            }
            if let Some(status) = status
                && stdout_closed
                && stderr_closed
            {
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if status.is_err() {
        terminate(&mut child);
    }
    let status = status?;
    if !status.success() {
        return Err(Error::new(
            "E_BUILD",
            &name,
            format!(
                "image tool failed ({status}): {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
        ));
    }
    Ok(stdout)
}
