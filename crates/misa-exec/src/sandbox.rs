//! Construction and read-back verification of the bubblewrap view.
//!
//! bubblewrap is only a mount/namespace constructor here. Its bind mounts are
//! always `nosuid`, and `nodev` unless a device bind is requested (bubblewrap
//! `bind-mount.c`: `new_flags = current | (devices ? 0 : MS_NODEV) | MS_NOSUID |
//! (readonly ? MS_RDONLY : 0)`), but this launcher does not assume it: the live
//! sandbox's `/proc/<pid>/mountinfo` is parsed while the payload is still blocked
//! before `exec`, and the launch aborts unless every mount is exactly one of the
//! expected ones with the expected flags.
use crate::{
    Error, Result,
    plan::{Export, Grant, GrantKind},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const MAX_USER_ARG_BYTES: usize = 1024 * 1024;

fn sandbox_error(field: &str, message: impl Into<String>) -> Error {
    Error::new("E_SANDBOX", field, message)
}

/// Pinned image tools only: an ambient host `bwrap` is not a trust anchor.
pub fn find_bwrap() -> Result<PathBuf> {
    let candidate = std::env::var_os("MISA_BWRAP")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|directory| directory.join("bwrap"))
                    .find(|path| path.is_file())
            })
        })
        .ok_or_else(|| {
            Error::new(
                "E_CAPABILITY",
                "bwrap",
                "pinned bubblewrap unavailable; use the packaged misa binary or nix develop",
            )
        })?;
    let resolved = candidate
        .canonicalize()
        .map_err(|_| Error::new("E_CAPABILITY", "bwrap", "cannot resolve bubblewrap"))?;
    if !resolved.starts_with("/nix/store") || !resolved.is_file() {
        return Err(Error::new(
            "E_CAPABILITY",
            "bwrap",
            "bubblewrap must come from the pinned Nix environment, not an ambient host binary",
        ));
    }
    Ok(resolved)
}

/// A grant whose host source was resolved and type-checked at launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedGrant {
    pub id: String,
    pub kind: GrantKind,
    pub source: PathBuf,
    pub target: String,
    pub writable: bool,
}

/// `/tmp` and `/run` are private tmpfs scratch mounts, so grant targets below
/// them need not exist in the sealed image.
fn on_scratch(target: &str) -> bool {
    ["/tmp", "/run"]
        .iter()
        .any(|root| target.starts_with(&format!("{root}/")))
}

fn image_node(rootfs: &Path, target: &str) -> Result<fs::Metadata> {
    let mut host = rootfs.to_path_buf();
    let mut last = None;
    for component in target.split('/').filter(|part| !part.is_empty()) {
        host.push(component);
        let metadata = fs::symlink_metadata(&host).map_err(|_| {
            sandbox_error(
                "grant.target",
                format!("{target} does not exist in the sealed root; the read-only root cannot create mount points"),
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new(
                "E_PATH_OWNER",
                "grant.target",
                format!("{target} traverses a symlink in the sealed root"),
            ));
        }
        last = Some(metadata);
    }
    last.ok_or_else(|| sandbox_error("grant.target", "grant target must not be the root"))
}

/// Mount points bubblewrap must find as real directories in the sealed image.
pub fn require_mount_points(rootfs: &Path) -> Result<()> {
    for target in ["/proc", "/dev", "/tmp", "/run"] {
        if !image_node(rootfs, target)?.is_dir() {
            return Err(sandbox_error(
                "mountpoint",
                format!("{target} is not a directory in the sealed root"),
            ));
        }
    }
    Ok(())
}

pub fn resolve_grants(export: &Export, store: &Path, rootfs: &Path) -> Result<Vec<ResolvedGrant>> {
    let mut resolved = Vec::new();
    for grant in &export.grants {
        resolved.push(resolve_grant(grant, store, rootfs)?);
    }
    // Parents before children; the plan already forbids overlapping targets.
    resolved.sort_by(|left, right| left.target.cmp(&right.target));
    Ok(resolved)
}

fn resolve_grant(grant: &Grant, store: &Path, rootfs: &Path) -> Result<ResolvedGrant> {
    if grant.target == "/tmp" || grant.target == "/run" {
        return Err(sandbox_error(
            "grant.target",
            "/tmp and /run are launcher-provided scratch mounts and cannot be grant targets",
        ));
    }
    let source = fs::canonicalize(&grant.source).map_err(|_| {
        sandbox_error(
            "grant.source",
            format!("grant {} source is missing on the host", grant.id),
        )
    })?;
    let metadata = fs::metadata(&source)
        .map_err(|_| sandbox_error("grant.source", "cannot inspect grant source"))?;
    let file_type = metadata.file_type();
    let matches = match grant.kind {
        GrantKind::Directory => file_type.is_dir(),
        GrantKind::File => file_type.is_file(),
        GrantKind::SessionSocket => std::os::unix::fs::FileTypeExt::is_socket(&file_type),
    };
    if !matches {
        return Err(sandbox_error(
            "grant.source",
            format!("grant {} source is not a {:?}", grant.id, grant.kind),
        ));
    }
    if source.starts_with(store) || store.starts_with(&source) {
        return Err(Error::new(
            "E_PATH_OWNER",
            "grant.source",
            "a grant may not expose or contain the retained store",
        ));
    }
    if !on_scratch(&grant.target) {
        let node = image_node(rootfs, &grant.target)?;
        let ok = match grant.kind {
            GrantKind::Directory => node.is_dir(),
            _ => node.is_file(),
        };
        if !ok {
            return Err(sandbox_error(
                "grant.target",
                format!(
                    "{} exists in the sealed root with the wrong type for a {:?} grant",
                    grant.target, grant.kind
                ),
            ));
        }
    }
    Ok(ResolvedGrant {
        id: grant.id.clone(),
        kind: grant.kind,
        source,
        target: grant.target.clone(),
        writable: grant.writable,
    })
}

fn display_ok(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("unix:")
        .or_else(|| value.strip_prefix(':'))
    else {
        return false;
    };
    let (display, screen) = match rest.split_once('.') {
        Some((display, screen)) => (display, Some(screen)),
        None => (rest, None),
    };
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    digits(display) && screen.is_none_or(digits)
}

fn socket_target<'a>(grants: &'a [ResolvedGrant], path: &str) -> Option<&'a ResolvedGrant> {
    grants
        .iter()
        .find(|grant| grant.kind == GrantKind::SessionSocket && grant.target == path)
}

/// The payload environment: exactly the plan's literals plus a default `PATH`.
/// Nothing is inherited. Desktop-session variables are accepted only when an
/// explicit grant of the matching kind delivers the endpoint they name.
pub fn environment(export: &Export, grants: &[ResolvedGrant]) -> Result<BTreeMap<String, String>> {
    let mut env = export.env.clone();
    env.entry("PATH".into())
        .or_insert_with(|| DEFAULT_PATH.into());
    if let Some(display) = env.get("DISPLAY") {
        let has_x11 = grants
            .iter()
            .any(|g| g.kind == GrantKind::Directory && g.target == "/tmp/.X11-unix");
        if !display_ok(display) || !has_x11 {
            return Err(sandbox_error(
                "env.DISPLAY",
                "DISPLAY needs a local display name and an explicit /tmp/.X11-unix directory grant; network X11 is refused",
            ));
        }
    }
    if let Some(authority) = env.get("XAUTHORITY")
        && !grants
            .iter()
            .any(|g| g.kind == GrantKind::File && &g.target == authority)
    {
        return Err(sandbox_error(
            "env.XAUTHORITY",
            "XAUTHORITY must name the target of an explicit file grant",
        ));
    }
    if let Some(display) = env.get("WAYLAND_DISPLAY") {
        let socket = if display.starts_with('/') {
            display.clone()
        } else {
            match env.get("XDG_RUNTIME_DIR") {
                Some(runtime) => format!("{}/{display}", runtime.trim_end_matches('/')),
                None => String::new(),
            }
        };
        if socket_target(grants, &socket).is_none() {
            return Err(sandbox_error(
                "env.WAYLAND_DISPLAY",
                "WAYLAND_DISPLAY must resolve to an explicit session-socket grant",
            ));
        }
    }
    if let Some(address) = env.get("DBUS_SESSION_BUS_ADDRESS") {
        let path = address
            .strip_prefix("unix:path=")
            .map(|rest| rest.split(',').next().unwrap_or(""));
        let granted = path.is_some_and(|path| socket_target(grants, path).is_some())
            && !address.contains(";");
        if !granted {
            return Err(sandbox_error(
                "env.DBUS_SESSION_BUS_ADDRESS",
                "only unix:path= addresses naming an explicit session-socket grant are allowed; abstract, tcp and exec transports are refused",
            ));
        }
    }
    Ok(env)
}

/// Everything needed to assemble the bubblewrap command line.
pub struct Plan<'a> {
    pub rootfs: &'a Path,
    pub export: &'a Export,
    pub user_args: &'a [OsString],
    pub grants: &'a [ResolvedGrant],
    pub env: &'a BTreeMap<String, String>,
    pub status_fd: i32,
    pub block_fd: i32,
}

/// bwrap argv. Namespaces are strict (`--unshare-user`, not `-try`): if user
/// namespaces are unavailable bubblewrap fails and the launch fails closed.
/// Nested user namespaces are disabled inside, the session is detached from the
/// terminal (TIOCSTI), and the sandbox dies with this process.
pub fn bwrap_args(plan: &Plan<'_>) -> Result<Vec<OsString>> {
    let total: usize = plan.user_args.iter().map(|arg| arg.as_bytes().len()).sum();
    if total > MAX_USER_ARG_BYTES {
        return Err(Error::new(
            "E_SCHEMA",
            "args",
            "user arguments exceed 1 MiB",
        ));
    }
    let mut args: Vec<OsString> = [
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--json-status-fd",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.push(plan.status_fd.to_string().into());
    args.push("--block-fd".into());
    args.push(plan.block_fd.to_string().into());
    args.push("--clearenv".into());
    for (name, value) in plan.env {
        args.extend(["--setenv".into(), name.into(), value.into()]);
    }
    args.extend([
        "--ro-bind".into(),
        plan.rootfs.as_os_str().to_owned(),
        "/".into(),
    ]);
    args.extend(["--proc", "/proc", "--dev", "/dev"].map(OsString::from));
    for (mode, target) in [("1777", "/tmp"), ("0755", "/run")] {
        args.extend(["--perms", mode, "--tmpfs", target].map(OsString::from));
    }
    for grant in plan.grants {
        let mode = if grant.writable {
            "--bind"
        } else {
            "--ro-bind"
        };
        args.push(mode.into());
        args.push(grant.source.as_os_str().to_owned());
        args.push(grant.target.clone().into());
    }
    args.extend(["--chdir", "/"].map(OsString::from));
    if let Some(argv0) = plan.export.argv.first() {
        args.extend(["--argv0".into(), argv0.into()]);
    }
    args.push("--".into());
    args.push(plan.export.program.clone().into());
    for declared in plan.export.argv.iter().skip(1) {
        args.push(declared.into());
    }
    args.extend(plan.user_args.iter().cloned());
    Ok(args)
}

struct Mount {
    device: (u32, u32),
    mount_point: String,
    options: BTreeSet<String>,
    fs_type: String,
}

fn unescape(field: &str) -> Result<String> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 4 <= bytes.len() {
            let digits = &bytes[index + 1..index + 4];
            if digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                let value = digits
                    .iter()
                    .fold(0u32, |acc, digit| acc * 8 + u32::from(digit - b'0'));
                out.push(value as u8);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).map_err(|_| sandbox_error("mountinfo", "non-UTF-8 mount point"))
}

fn parse_mountinfo(text: &str) -> Result<Vec<Mount>> {
    let malformed = || sandbox_error("mountinfo", "malformed mountinfo line");
    let mut mounts = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (left, right) = line.split_once(" - ").ok_or_else(malformed)?;
        let fields: Vec<&str> = left.split(' ').collect();
        if fields.len() < 6 {
            return Err(malformed());
        }
        let (major, minor) = fields[2].split_once(':').ok_or_else(malformed)?;
        let fs_type = right.split(' ').next().ok_or_else(malformed)?.to_owned();
        mounts.push(Mount {
            device: (
                major.parse().map_err(|_| malformed())?,
                minor.parse().map_err(|_| malformed())?,
            ),
            mount_point: unescape(fields[4])?,
            options: fields[5].split(',').map(str::to_owned).collect(),
            fs_type,
        });
    }
    Ok(mounts)
}

/// `(major, minor)` of a `st_dev`, as printed by `/proc/<pid>/mountinfo`.
pub fn split_dev(dev: u64) -> (u32, u32) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major as u32, minor as u32)
}

/// Verify the complete mount set of the still-blocked sandbox.
///
/// `/` must be the sealed root's filesystem mounted `ro,nosuid,nodev`; `/proc`,
/// `/dev`, `/tmp`, `/run` and each grant must carry `nosuid,nodev` (device nodes
/// only `nosuid`, by design), grants `ro` exactly when not writable. Any other,
/// missing, or duplicated mount (including a leftover host old root) fails.
pub fn verify_mountinfo(
    text: &str,
    root_device: (u32, u32),
    grants: &[ResolvedGrant],
) -> Result<()> {
    let mounts = parse_mountinfo(text)?;
    let mut seen = BTreeSet::new();
    let device_nodes = [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
        "/dev/console",
    ];
    for mount in &mounts {
        let point = mount.mount_point.as_str();
        let grant = grants.iter().find(|grant| grant.target == point);
        let (needs, fs_type): (&[&str], Option<&str>) = if point == "/" {
            if mount.device != root_device {
                return Err(sandbox_error(
                    "mountinfo",
                    "the sandbox root is not the sealed root's filesystem",
                ));
            }
            (&["ro", "nosuid", "nodev"], None)
        } else if point == "/proc" {
            (&["nosuid", "nodev", "noexec"], Some("proc"))
        } else if point == "/dev" || point == "/tmp" || point == "/run" {
            (&["nosuid", "nodev"], Some("tmpfs"))
        } else if point == "/dev/pts" {
            (&["nosuid", "noexec"], Some("devpts"))
        } else if device_nodes.contains(&point) {
            (&["nosuid"], None)
        } else if grant.is_some() {
            (&["nosuid", "nodev"], None)
        } else {
            return Err(sandbox_error(
                "mountinfo",
                format!("unexpected mount {point:?} in the sandbox"),
            ));
        };
        for option in needs {
            if !mount.options.contains(*option) {
                return Err(sandbox_error(
                    "mountinfo",
                    format!("mount {point:?} lacks the required {option} flag"),
                ));
            }
        }
        if fs_type.is_some_and(|expected| expected != mount.fs_type) {
            return Err(sandbox_error(
                "mountinfo",
                format!("mount {point:?} has an unexpected filesystem type"),
            ));
        }
        if let Some(grant) = grant
            && point != "/"
            && mount.options.contains("ro") == grant.writable
        {
            return Err(sandbox_error(
                "mountinfo",
                format!(
                    "grant {} writability differs from its declaration",
                    grant.id
                ),
            ));
        }
        if !seen.insert(point.to_owned()) {
            return Err(sandbox_error(
                "mountinfo",
                format!("mount {point:?} is stacked more than once"),
            ));
        }
    }
    let required = ["/", "/proc", "/dev", "/tmp", "/run"]
        .into_iter()
        .map(str::to_owned)
        .chain(grants.iter().map(|grant| grant.target.clone()));
    for point in required {
        if !seen.contains(&point) {
            return Err(sandbox_error(
                "mountinfo",
                format!("expected mount {point:?} is absent from the sandbox"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn export(env: &[(&str, &str)]) -> Export {
        Export {
            id: "app".into(),
            name: "app".into(),
            program: "/usr/bin/app".into(),
            argv: vec!["app".into(), "--declared".into()],
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            grants: Vec::new(),
        }
    }

    fn grant(kind: GrantKind, source: &str, target: &str, writable: bool) -> ResolvedGrant {
        ResolvedGrant {
            id: "g".into(),
            kind,
            source: source.into(),
            target: target.into(),
            writable,
        }
    }

    const ROOT: &str = "512 113 254:1 /store/rootfs / ro,nosuid,nodev,relatime master:1 - ext4 /dev/x rw\n\
515 512 0:126 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
519 512 0:127 / /dev rw,nosuid,nodev,relatime - tmpfs tmpfs rw,mode=755\n\
520 519 0:7 /null /dev/null rw,nosuid master:10 - devtmpfs devtmpfs rw\n\
526 519 0:128 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw\n\
527 512 0:129 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs rw\n\
531 512 0:130 / /run rw,nosuid,nodev,relatime - tmpfs tmpfs rw,mode=755\n";

    #[test]
    fn the_real_bubblewrap_mount_shape_is_accepted() {
        verify_mountinfo(ROOT, (254, 1), &[]).unwrap();
    }

    #[test]
    fn a_root_missing_nosuid_nodev_or_ro_is_refused() {
        for flags in ["rw,nosuid,nodev", "ro,nodev", "ro,nosuid"] {
            let text = ROOT.replacen("ro,nosuid,nodev", flags, 1);
            let error = verify_mountinfo(&text, (254, 1), &[]).unwrap_err();
            assert_eq!(error.code, "E_SANDBOX", "{flags}");
        }
    }

    #[test]
    fn a_root_on_another_filesystem_or_a_leftover_old_root_is_refused() {
        assert!(verify_mountinfo(ROOT, (8, 1), &[]).is_err());
        let leaked = format!("{ROOT}600 512 254:1 / /oldroot rw,relatime - ext4 /dev/x rw\n");
        let error = verify_mountinfo(&leaked, (254, 1), &[]).unwrap_err();
        assert!(error.message.contains("unexpected mount"));
    }

    #[test]
    fn missing_or_stacked_mounts_are_refused() {
        let without_tmp: String = ROOT
            .lines()
            .filter(|line| !line.contains(" /tmp "))
            .map(|line| format!("{line}\n"))
            .collect();
        assert!(verify_mountinfo(&without_tmp, (254, 1), &[]).is_err());
        let stacked = format!("{ROOT}540 512 0:131 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n");
        assert!(verify_mountinfo(&stacked, (254, 1), &[]).is_err());
    }

    #[test]
    fn grants_must_match_declared_writability_and_carry_nosuid_nodev() {
        let ro = grant(GrantKind::Directory, "/src", "/mnt/data", false);
        let rw = grant(GrantKind::Directory, "/src", "/mnt/data", true);
        let line = |options: &str| {
            format!("{ROOT}541 512 254:1 /src /mnt/data {options} master:1 - ext4 /dev/x rw\n")
        };
        verify_mountinfo(
            &line("ro,nosuid,nodev,relatime"),
            (254, 1),
            std::slice::from_ref(&ro),
        )
        .unwrap();
        verify_mountinfo(
            &line("rw,nosuid,nodev,relatime"),
            (254, 1),
            std::slice::from_ref(&rw),
        )
        .unwrap();
        assert!(
            verify_mountinfo(
                &line("rw,nosuid,nodev"),
                (254, 1),
                std::slice::from_ref(&ro)
            )
            .is_err()
        );
        assert!(verify_mountinfo(&line("ro,nosuid,nodev"), (254, 1), &[rw]).is_err());
        assert!(verify_mountinfo(&line("ro,nodev"), (254, 1), std::slice::from_ref(&ro)).is_err());
        assert!(
            verify_mountinfo(ROOT, (254, 1), &[ro]).is_err(),
            "a declared grant that never mounted must fail"
        );
    }

    #[test]
    fn mount_points_with_spaces_are_unescaped() {
        let g = grant(GrantKind::Directory, "/src", "/mnt/my data", false);
        let text =
            format!("{ROOT}541 512 254:1 /src /mnt/my\\040data ro,nosuid,nodev - ext4 /dev/x rw\n");
        verify_mountinfo(&text, (254, 1), &[g]).unwrap();
    }

    #[test]
    fn st_dev_decodes_like_mountinfo() {
        assert_eq!(split_dev((254 << 8) | 1), (254, 1));
        assert_eq!(split_dev(0x10301), (259, 1));
        assert_eq!(split_dev(0x0011_0323), (259, 0x123));
    }

    #[test]
    fn environment_is_only_literals_plus_default_path() {
        let env = environment(&export(&[("LANG", "C.UTF-8")]), &[]).unwrap();
        assert_eq!(env["LANG"], "C.UTF-8");
        assert_eq!(env["PATH"], DEFAULT_PATH);
        assert_eq!(env.len(), 2);
        let declared = environment(&export(&[("PATH", "/opt/bin")]), &[]).unwrap();
        assert_eq!(declared["PATH"], "/opt/bin");
    }

    #[test]
    fn session_variables_require_matching_explicit_grants() {
        let x11 = grant(
            GrantKind::Directory,
            "/tmp/.X11-unix",
            "/tmp/.X11-unix",
            true,
        );
        let auth = grant(
            GrantKind::File,
            "/home/u/.Xauthority",
            "/tmp/.Xauthority",
            false,
        );
        let env = [("DISPLAY", ":0"), ("XAUTHORITY", "/tmp/.Xauthority")];
        assert_eq!(
            environment(&export(&env), &[]).unwrap_err().field,
            "env.DISPLAY"
        );
        assert_eq!(
            environment(&export(&env), std::slice::from_ref(&x11))
                .unwrap_err()
                .field,
            "env.XAUTHORITY"
        );
        environment(&export(&env), &[x11.clone(), auth.clone()]).unwrap();
        for display in ["host:0", "tcp/host:6000", ":a", "unix:", ":0.x"] {
            assert!(
                environment(&export(&[("DISPLAY", display)]), std::slice::from_ref(&x11)).is_err(),
                "{display}"
            );
        }
        for display in [":0", ":1.0", "unix:0"] {
            environment(&export(&[("DISPLAY", display)]), std::slice::from_ref(&x11)).unwrap();
        }
    }

    #[test]
    fn dbus_and_wayland_need_explicit_session_socket_grants() {
        let bus = grant(
            GrantKind::SessionSocket,
            "/run/user/1000/bus",
            "/run/user/1000/bus",
            true,
        );
        let wayland = grant(
            GrantKind::SessionSocket,
            "/run/user/1000/wayland-0",
            "/run/user/1000/wayland-0",
            true,
        );
        let address = "unix:path=/run/user/1000/bus,guid=abc";
        assert!(environment(&export(&[("DBUS_SESSION_BUS_ADDRESS", address)]), &[]).is_err());
        environment(
            &export(&[("DBUS_SESSION_BUS_ADDRESS", address)]),
            std::slice::from_ref(&bus),
        )
        .unwrap();
        for hostile in [
            "unix:abstract=/tmp/dbus-x",
            "tcp:host=h,port=1",
            "unixexec:path=/bin/sh",
            "unix:path=/run/user/1000/other",
        ] {
            assert!(
                environment(
                    &export(&[("DBUS_SESSION_BUS_ADDRESS", hostile)]),
                    std::slice::from_ref(&bus)
                )
                .is_err(),
                "{hostile}"
            );
        }
        let env = [
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ];
        assert!(environment(&export(&env), &[bus]).is_err());
        environment(&export(&env), std::slice::from_ref(&wayland)).unwrap();
        environment(
            &export(&[("WAYLAND_DISPLAY", "/run/user/1000/wayland-0")]),
            &[wayland],
        )
        .unwrap();
    }

    #[test]
    fn argv_is_exactly_the_declared_program_argv_then_user_args() {
        let export = export(&[("LANG", "C")]);
        let env = environment(&export, &[]).unwrap();
        let user = [OsString::from("--help"), OsString::from("; rm -rf /")];
        let args = bwrap_args(&Plan {
            rootfs: Path::new("/store/materialized/aa/rootfs"),
            export: &export,
            user_args: &user,
            grants: &[grant(GrantKind::Directory, "/data", "/mnt/data", true)],
            env: &env,
            status_fd: 5,
            block_fd: 6,
        })
        .unwrap();
        let text: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let at = |needle: &str| text.iter().position(|a| a == needle).unwrap();
        for namespace in [
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ] {
            assert!(text.contains(&namespace.to_owned()), "{namespace}");
        }
        assert!(
            !text
                .iter()
                .any(|a| a == "--share-net" || a == "--unshare-user-try")
        );
        assert_eq!(
            &text[at("--ro-bind")..at("--ro-bind") + 3],
            ["--ro-bind", "/store/materialized/aa/rootfs", "/"]
        );
        assert_eq!(
            &text[at("--bind")..at("--bind") + 3],
            ["--bind", "/data", "/mnt/data"]
        );
        let separator = at("--");
        assert_eq!(
            &text[separator..],
            ["--", "/usr/bin/app", "--declared", "--help", "; rm -rf /"]
        );
        assert_eq!(&text[at("--argv0")..at("--argv0") + 2], ["--argv0", "app"]);
        // The environment is the only thing set; nothing is inherited.
        assert!(text.windows(3).any(|w| w == ["--setenv", "LANG", "C"]));
    }

    #[test]
    fn grants_reject_missing_sources_wrong_types_store_overlap_and_scratch_targets() {
        let root = tempfile::tempdir().unwrap();
        let rootfs = root.path().join("rootfs");
        for dir in ["proc", "dev", "tmp", "run", "mnt/share"] {
            fs::create_dir_all(rootfs.join(dir)).unwrap();
        }
        fs::write(rootfs.join("etc.conf"), b"").unwrap();
        std::os::unix::fs::symlink("/mnt/share", rootfs.join("link")).unwrap();
        require_mount_points(&rootfs).unwrap();
        let store = root.path().join("store");
        fs::create_dir_all(&store).unwrap();
        let share = root.path().join("share");
        fs::create_dir_all(&share).unwrap();
        let socket_path = root.path().join("bus");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let g = |kind, source: &Path, target: &str| Grant {
            id: "g".into(),
            kind,
            source: source.to_str().unwrap().into(),
            target: target.into(),
            writable: false,
        };
        let ok = resolve_grant(
            &g(GrantKind::Directory, &share, "/mnt/share"),
            &store,
            &rootfs,
        );
        assert!(ok.is_ok());
        let on_scratch = resolve_grant(
            &g(GrantKind::SessionSocket, &socket_path, "/run/user/1000/bus"),
            &store,
            &rootfs,
        );
        assert!(on_scratch.is_ok());
        let cases = [
            (
                "missing source",
                g(
                    GrantKind::Directory,
                    &root.path().join("nope"),
                    "/mnt/share",
                ),
                "E_SANDBOX",
            ),
            (
                "dir given as file",
                g(GrantKind::File, &share, "/etc.conf"),
                "E_SANDBOX",
            ),
            (
                "socket given as dir",
                g(GrantKind::Directory, &socket_path, "/mnt/share"),
                "E_SANDBOX",
            ),
            (
                "store overlap",
                g(GrantKind::Directory, &store, "/mnt/share"),
                "E_PATH_OWNER",
            ),
            (
                "store ancestor",
                g(GrantKind::Directory, root.path(), "/mnt/share"),
                "E_PATH_OWNER",
            ),
            (
                "absent target",
                g(GrantKind::Directory, &share, "/mnt/absent"),
                "E_SANDBOX",
            ),
            (
                "symlink target",
                g(GrantKind::Directory, &share, "/link"),
                "E_PATH_OWNER",
            ),
            (
                "tmp itself",
                g(GrantKind::Directory, &share, "/tmp"),
                "E_SANDBOX",
            ),
            (
                "type mismatch",
                g(GrantKind::Directory, &share, "/etc.conf"),
                "E_SANDBOX",
            ),
        ];
        for (name, grant, code) in cases {
            let error = resolve_grant(&grant, &store, &rootfs).unwrap_err();
            assert_eq!(error.code, code, "{name}: {error}");
        }
    }

    #[test]
    fn mount_points_missing_from_the_image_fail_before_spawn() {
        let root = tempfile::tempdir().unwrap();
        for dir in ["proc", "dev", "run"] {
            fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        assert_eq!(
            require_mount_points(root.path()).unwrap_err().code,
            "E_SANDBOX"
        );
    }
}
