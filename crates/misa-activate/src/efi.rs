//! Boot Loader Interface variables, read from efivarfs (B6).
//!
//! `LoaderFeatures` describes only the loader of the *running* boot, so a strategy
//! other than `manual` is chosen from this record after one successful boot.
use misa_plan::{Error, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;

pub const LOADER_VENDOR: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoaderInfo {
    pub loader: Option<String>,
    pub entry_selected: Option<String>,
    pub features: Option<String>,
    pub config_timeout: bool,
    pub entry_default: bool,
    pub entry_one_shot: bool,
    pub boot_counting: bool,
    pub boot_count_path: Option<String>,
}

fn variable(dir: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    match fs::read(dir.join(format!("{name}-{LOADER_VENDOR}"))) {
        Ok(bytes) if bytes.len() >= 4 => Ok(Some(bytes[4..].to_vec())),
        Ok(_) => Err(Error::new(
            "E_BOOT_LOADER",
            name.to_owned(),
            "truncated EFI variable",
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::new("E_BOOT_LOADER", name.to_owned(), e.to_string())),
    }
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn read(efivars: &Path) -> Result<LoaderInfo> {
    let features = variable(efivars, "LoaderFeatures")?
        .map(|b| {
            if b.len() < 8 {
                return Err(Error::new(
                    "E_BOOT_LOADER",
                    "LoaderFeatures",
                    "expected a 64-bit mask",
                ));
            }
            Ok(u64::from_le_bytes(b[..8].try_into().unwrap()))
        })
        .transpose()?;
    let bit = |n: u32| features.is_some_and(|f| f & (1 << n) != 0);
    Ok(LoaderInfo {
        loader: variable(efivars, "LoaderInfo")?.map(|b| utf16(&b)),
        entry_selected: variable(efivars, "LoaderEntrySelected")?.map(|b| utf16(&b)),
        features: features.map(|f| format!("{f:#x}")),
        config_timeout: bit(0),
        entry_default: bit(2),
        entry_one_shot: bit(3),
        boot_counting: bit(4),
        boot_count_path: variable(efivars, "LoaderBootCountPath")?.map(|b| utf16(&b)),
    })
}
