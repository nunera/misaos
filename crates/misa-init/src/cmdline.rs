//! Strict parse of the `misa.*` kernel command-line keys (Chapter 12, H1).
//!
//! Other tokens belong to the kernel or the borrowed stage 1 and are ignored. Every
//! `misa.` key must be known and appear once; unknown keys fail closed.
use misa_plan::{Error, Result};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    pub kind: String,
    pub value: String,
}

impl Selector {
    pub fn render(&self) -> String {
        format!("{}={}", self.kind, self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmdline {
    /// 64 lowercase hex digits naming the generation.
    pub generation: String,
    pub root: Selector,
    pub wait: Option<u32>,
    /// `sha256:` digest of the exact command-line bytes.
    pub digest: String,
}

fn err(field: &str, message: impl Into<String>) -> Error {
    Error::new("E_BOOT_CMDLINE", field.to_owned(), message)
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn parse(raw: &str) -> Result<Cmdline> {
    let mut generation = None;
    let mut root = None;
    let mut wait = None;
    for token in raw.split_ascii_whitespace() {
        let Some(rest) = token.strip_prefix("misa.") else {
            continue;
        };
        let (key, value) = rest.split_once('=').unwrap_or((rest, ""));
        let field = format!("misa.{key}");
        let slot_taken = match key {
            "generation" => generation.is_some(),
            "root" => root.is_some(),
            "wait" => wait.is_some(),
            "rescue" | "select" => {
                return Err(err(
                    &field,
                    "the rescue menu is not part of the borrowed stage-1 boot path",
                ));
            }
            _ => return Err(err(&field, "unknown misa.* key")),
        };
        if slot_taken {
            return Err(err(&field, "key given more than once"));
        }
        match key {
            "generation" => {
                if !hex64(value) {
                    return Err(err(&field, "expected 64 lowercase hex digits"));
                }
                generation = Some(value.to_owned());
            }
            "root" => {
                let (kind, id) = value
                    .split_once('=')
                    .ok_or_else(|| err(&field, "expected KIND=VALUE"))?;
                if !matches!(kind, "partuuid" | "fsuuid" | "luksuuid") || id.is_empty() {
                    return Err(err(
                        &field,
                        "selector kind must be partuuid, fsuuid or luksuuid",
                    ));
                }
                root = Some(Selector {
                    kind: kind.to_owned(),
                    value: id.to_owned(),
                });
            }
            _ => {
                wait = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| err(&field, "expected whole seconds"))?,
                );
            }
        }
    }
    Ok(Cmdline {
        generation: generation.ok_or_else(|| err("misa.generation", "required"))?,
        root: root.ok_or_else(|| err("misa.root", "required"))?,
        wait,
        digest: format!("sha256:{:x}", Sha256::digest(raw.as_bytes())),
    })
}
