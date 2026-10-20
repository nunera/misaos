//! Just enough ELF to check V10: class, byte order, machine and `PT_INTERP`.
use misa_plan::{Error, Result};

const PT_INTERP: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub struct ElfInfo {
    pub machine: u16,
    pub interpreter: Option<String>,
}

fn invalid(message: &str) -> Error {
    Error::new("E_BOOT_INIT_INVALID", "/boot/init/path", message)
}

fn u16_at(b: &[u8], at: usize) -> Result<u16> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| invalid("truncated ELF header"))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| invalid("truncated ELF header"))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64> {
    b.get(at..at + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| invalid("truncated ELF header"))
}

/// Parse a little-endian ELF64 executable image.
pub fn inspect(bytes: &[u8]) -> Result<ElfInfo> {
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Err(invalid("not an ELF file"));
    }
    if bytes.get(4) != Some(&2) || bytes.get(5) != Some(&1) {
        return Err(invalid("init must be a little-endian 64-bit ELF"));
    }
    let machine = u16_at(bytes, 18)?;
    let phoff = usize::try_from(u64_at(bytes, 32)?).map_err(|_| invalid("bad e_phoff"))?;
    let phentsize = usize::from(u16_at(bytes, 54)?);
    let phnum = usize::from(u16_at(bytes, 56)?);
    if phentsize < 56 {
        return Err(invalid("bad e_phentsize"));
    }
    let mut interpreter = None;
    for i in 0..phnum {
        let header = phoff
            .checked_add(
                i.checked_mul(phentsize)
                    .ok_or_else(|| invalid("bad e_phnum"))?,
            )
            .ok_or_else(|| invalid("bad e_phoff"))?;
        if u32_at(bytes, header)? != PT_INTERP {
            continue;
        }
        let offset =
            usize::try_from(u64_at(bytes, header + 8)?).map_err(|_| invalid("bad p_offset"))?;
        let size =
            usize::try_from(u64_at(bytes, header + 32)?).map_err(|_| invalid("bad p_filesz"))?;
        let raw = offset
            .checked_add(size)
            .and_then(|end| bytes.get(offset..end))
            .ok_or_else(|| invalid("PT_INTERP lies outside the file"))?;
        let raw = raw.strip_suffix(b"\0").unwrap_or(raw);
        interpreter =
            Some(String::from_utf8(raw.to_vec()).map_err(|_| invalid("PT_INTERP is not UTF-8"))?);
    }
    Ok(ElfInfo {
        machine,
        interpreter,
    })
}
