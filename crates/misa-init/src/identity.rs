//! Confirm, by on-disk content, that the mounted root is the device the selector names.
//!
//! The borrowed stage 1 found and mounted the root; this check does not trust how. A
//! `partuuid` is read from the parent disk's GPT entry whose first LBA is the
//! partition's start sector; an `fsuuid` from the ext4 superblock.
use crate::cmdline::Selector;
use misa_plan::{Error, Result};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RootIdentity {
    pub device: String,
    pub verified_by: &'static str,
}

fn mismatch(message: impl Into<String>) -> Error {
    Error::new("E_BOOT_ROOT_SELECTOR", "/boot/root/selector", message)
}

fn read_at(file: &mut File, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0; len];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut buf))
        .map_err(|e| mismatch(format!("cannot read root device: {e}")))?;
    Ok(buf)
}

/// RFC 4122 text of a GPT/ext4 GUID stored in mixed-endian (GPT) or big-endian (ext4) form.
fn guid(bytes: &[u8], mixed_endian: bool) -> String {
    let b: Vec<u8> = if mixed_endian {
        let mut v = bytes.to_vec();
        v[0..4].reverse();
        v[4..6].reverse();
        v[6..8].reverse();
        v
    } else {
        bytes.to_vec()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sys_value(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .map_err(|e| mismatch(format!("{}: {e}", path.display())))
}

fn gpt_partuuid(disk: &Path, start_sector: u64) -> Result<String> {
    let mut file = File::open(disk).map_err(|e| mismatch(format!("{}: {e}", disk.display())))?;
    let header = read_at(&mut file, 512, 92)?;
    if &header[0..8] != b"EFI PART" {
        return Err(mismatch("root disk has no GPT header"));
    }
    let entries_lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(header[80..84].try_into().unwrap());
    let size = u32::from_le_bytes(header[84..88].try_into().unwrap());
    if !(128..=4096).contains(&size) || count > 1024 {
        return Err(mismatch("implausible GPT entry table"));
    }
    let table = read_at(&mut file, entries_lba * 512, (count * size) as usize)?;
    table
        .chunks(size as usize)
        .find(|e| {
            u64::from_le_bytes(e[32..40].try_into().unwrap()) == start_sector && e[0..16] != [0; 16]
        })
        .map(|e| guid(&e[16..32], true))
        .ok_or_else(|| mismatch("no GPT entry starts at the root partition"))
}

fn ext4_uuid(device: &Path) -> Result<String> {
    let mut file =
        File::open(device).map_err(|e| mismatch(format!("{}: {e}", device.display())))?;
    let sb = read_at(&mut file, 1024, 256)?;
    if u16::from_le_bytes([sb[0x38], sb[0x39]]) != 0xef53 {
        return Err(mismatch("root is not an ext4 file system"));
    }
    Ok(guid(&sb[0x68..0x78], false))
}

/// Identify the block device mounted at `/` and compare it with `selector`.
pub fn verify_mounted_root(selector: &Selector) -> Result<RootIdentity> {
    let dev = fs::metadata("/")
        .map_err(|e| mismatch(e.to_string()))?
        .dev();
    // SAFETY: major/minor are pure bit extraction.
    let (major, minor) = (libc::major(dev), libc::minor(dev));
    let sys = Path::new("/sys/dev/block").join(format!("{major}:{minor}"));
    let uevent = sys_value(&sys.join("uevent"))?;
    let name = uevent
        .lines()
        .find_map(|l| l.strip_prefix("DEVNAME="))
        .ok_or_else(|| mismatch("root device has no DEVNAME"))?
        .to_owned();
    let device = Path::new("/dev").join(&name);
    let (found, verified_by) = match selector.kind.as_str() {
        "partuuid" => {
            let start: u64 = sys_value(&sys.join("start"))?
                .parse()
                .map_err(|_| mismatch("root is not a partition"))?;
            let parent = fs::canonicalize(&sys)
                .map_err(|e| mismatch(e.to_string()))?
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| Path::new("/dev").join(n))
                .ok_or_else(|| mismatch("root partition has no parent disk"))?;
            (gpt_partuuid(&parent, start)?, "gpt-partition-guid")
        }
        "fsuuid" => (ext4_uuid(&device)?, "ext4-superblock-uuid"),
        _ => return Err(mismatch("LUKS roots are not part of the S3 cell")),
    };
    if found != selector.value.to_ascii_lowercase() {
        return Err(mismatch(format!(
            "mounted root {} is {}={found}, not {}",
            device.display(),
            selector.kind,
            selector.value
        )));
    }
    Ok(RootIdentity {
        device: device.display().to_string(),
        verified_by,
    })
}
