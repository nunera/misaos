//! As PID 1 (the borrowed stage 1's `switch_root` target): verify, record, exec init.
//! Otherwise: `misa-handoff --root DIR --cmdline-file FILE [--arch A --release R]`
//! runs the same checks against a fixture root and prints the handoff record.
use misa_init::{
    HandoffRecord, InitRecord, Monotonic, RootRecord, cmdline, identity, machine, monotonic_ns,
    verify::{self, Machine, Verified},
};
use misa_plan::{Error, Result};
use std::ffi::CString;
use std::fs;
use std::os::unix::{fs::MetadataExt, process::CommandExt};
use std::path::Path;

const DINIT_SERVICES: &str = "/run/misa/dinit/services";

fn state(field: &str, e: impl std::fmt::Display) -> Error {
    Error::new("E_BOOT_STATE", field.to_owned(), e.to_string())
}

fn ensure_mount(target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> Result<()> {
    fs::create_dir_all(target).map_err(|e| state(target, e))?;
    let root = fs::metadata("/").map_err(|e| state("/", e))?.dev();
    if fs::metadata(target).map_err(|e| state(target, e))?.dev() != root {
        return Ok(()); // the stage 1 moved its mount here already
    }
    let c = |s: &str| CString::new(s).expect("static mount argument");
    let (src, dst, ty, opts) = (c(fstype), c(target), c(fstype), c(data));
    // SAFETY: all pointers are valid NUL-terminated strings for the call's duration.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            ty.as_ptr(),
            flags,
            opts.as_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(state(target, std::io::Error::last_os_error()));
    }
    Ok(())
}

fn replace_symlink(target: &str, link: &str) -> Result<()> {
    let tmp = format!("{link}.misa-new");
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp).map_err(|e| state(link, e))?;
    fs::rename(&tmp, link).map_err(|e| state(link, e))
}

fn record(
    v: &Verified,
    cmd: &cmdline::Cmdline,
    root: Option<&identity::RootIdentity>,
    start: u64,
) -> Result<Vec<u8>> {
    let record = HandoffRecord {
        schema_version: "misa.handoff/v1",
        generation: &v.generation,
        plan: &v.plan,
        top_level: &v.top_level,
        stage1: "borrowed",
        initrd_build_id_check: "not-applicable-borrowed-stage1",
        root: RootRecord {
            selector: v.selector.render(),
            device: root.map(|r| r.device.as_str()),
            verified_by: root.map(|r| r.verified_by),
        },
        unlock_method: &v.unlock_method,
        cmdline_sha256: &cmd.digest,
        init: InitRecord {
            path: &v.init_path,
            sha256: &v.init_sha256,
            adapter_id: &v.adapter_id,
            adapter_build_id: &v.adapter_build_id,
        },
        journal: v.journal,
        checks: &v.checks,
        monotonic_ns: Monotonic {
            start,
            verified: monotonic_ns(),
        },
    };
    serde_jcs::to_vec(&record).map_err(|e| state("/run/misa/handoff.json", e))
}

fn pid1() -> Error {
    let start = monotonic_ns();
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    let prepared = ensure_mount("/proc", "proc", flags, "")
        .and_then(|()| ensure_mount("/sys", "sysfs", flags, ""))
        .and_then(|()| ensure_mount("/dev", "devtmpfs", libc::MS_NOSUID, "mode=0755"))
        .and_then(|()| {
            ensure_mount(
                "/run",
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV,
                "mode=0755",
            )
        });
    if let Err(e) = prepared {
        return e;
    }
    let raw = match fs::read_to_string("/proc/cmdline") {
        Ok(raw) => raw,
        Err(e) => return state("/proc/cmdline", e),
    };
    let result = cmdline::parse(raw.trim_end()).and_then(|cmd| {
        let verified = verify::verify(Path::new("/"), &cmd, &machine())?;
        let root = identity::verify_mounted_root(&verified.selector)?;
        if verified.adapter_id != "dinit" {
            return Err(Error::new(
                "E_BOOT_INIT_INVALID",
                "/boot/init/adapterId",
                "no handoff is defined for this init adapter",
            ));
        }
        let bytes = record(&verified, &cmd, Some(&root), start)?;
        fs::create_dir_all("/run/misa/dinit").map_err(|e| state("/run/misa", e))?;
        fs::write("/run/misa/handoff.json.misa-new", &bytes)
            .and_then(|()| fs::rename("/run/misa/handoff.json.misa-new", "/run/misa/handoff.json"))
            .map_err(|e| state("/run/misa/handoff.json", e))?;
        replace_symlink(&verified.top_level, "/run/current-system")?;
        replace_symlink(&verified.top_level, "/run/booted-system")?;
        replace_symlink(
            &format!("{}/{}", verified.top_level, verify::INIT_TREE),
            DINIT_SERVICES,
        )?;
        Ok(verified)
    });
    let verified = match result {
        Ok(verified) => verified,
        Err(error) => return error,
    };
    eprintln!(
        "misa-handoff: verified generation {} ({}); exec {}",
        verified.generation,
        verified.checks.join(","),
        verified.init_path
    );
    let error = std::process::Command::new(&verified.init_path)
        .arg0("dinit")
        .args(["--services-dir", DINIT_SERVICES])
        .env_clear()
        .current_dir("/")
        .exec();
    Error::new(
        "E_BOOT_INIT_INVALID",
        "/boot/init/path",
        format!("exec: {error}"),
    )
}

fn halt(error: &Error) -> ! {
    let line = format!(
        "misa-handoff: refused {}",
        serde_json::json!({"code": error.code, "field": error.field, "message": error.message})
    );
    eprintln!("{line}");
    let _ = fs::write("/dev/kmsg", format!("<2>{line}\n"));
    // SAFETY: flushing and halting are the only remaining actions of this PID 1.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_HALT_SYSTEM);
    }
    loop {
        // SAFETY: pause only waits for a signal.
        unsafe { libc::pause() };
    }
}

fn dry_run(args: &[String]) -> Result<Vec<u8>> {
    let mut opts = std::collections::BTreeMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| Error::new("E_USAGE", flag.clone(), "missing value"))?;
        opts.insert(flag.as_str(), value.as_str());
    }
    let need = |k: &str| {
        opts.get(k)
            .copied()
            .ok_or_else(|| Error::new("E_USAGE", k.to_owned(), "required"))
    };
    let running = machine();
    let machine = Machine {
        arch: opts.get("--arch").map_or(running.arch, |s| (*s).to_owned()),
        release: opts
            .get("--release")
            .map_or(running.release, |s| (*s).to_owned()),
    };
    let raw =
        fs::read_to_string(need("--cmdline-file")?).map_err(|e| state("--cmdline-file", e))?;
    let cmd = cmdline::parse(raw.trim_end())?;
    let verified = verify::verify(Path::new(need("--root")?), &cmd, &machine)?;
    record(&verified, &cmd, None, 0)
}

fn main() {
    if std::process::id() == 1 {
        let error = pid1();
        halt(&error);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dry_run(&args) {
        Ok(bytes) => println!("{}", String::from_utf8_lossy(&bytes)),
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"code": error.code, "field": error.field, "message": error.message})
            );
            std::process::exit(2);
        }
    }
}
