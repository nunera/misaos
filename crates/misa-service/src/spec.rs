//! `misa.svcrun/v1`: the per-service record `misa-svcrun` reads instead of a shell string.
use crate::graph::{Directory, EnvValue, Identity, Process, Readiness};
use misa_plan::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: &str = "misa.svcrun/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SvcrunSpec {
    pub schema_version: String,
    pub id: String,
    pub command: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub identity: Identity,
    /// Descriptor the service writes its readiness newline to, if any (R1).
    pub readiness_fd: Option<u32>,
    pub directories: Vec<SpecDirectory>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecDirectory {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub lifetime: String,
}

fn directory(index: usize, d: &Directory) -> Result<SpecDirectory> {
    let mode = u32::from_str_radix(&d.mode, 8).map_err(|_| {
        Error::new(
            "E_SCHEMA",
            format!("/directories/{index}/mode"),
            "mode is not octal",
        )
    })?;
    if d.lifetime == "runtime" && !d.path.starts_with("/run/") {
        return Err(Error::new(
            "E_PATH_OWNER",
            format!("/directories/{index}/path"),
            "runtime directories live under /run",
        ));
    }
    Ok(SpecDirectory {
        path: d.path.clone(),
        uid: d.owner.uid,
        gid: d.owner.gid,
        mode,
        lifetime: d.lifetime.clone(),
    })
}

impl SvcrunSpec {
    pub fn from_process(process: &Process) -> Result<Self> {
        let mut env = BTreeMap::new();
        for (name, value) in &process.env {
            match value {
                EnvValue::Literal { value } => {
                    env.insert(name.clone(), value.clone());
                }
                EnvValue::Secret { .. } => {
                    return Err(Error::new(
                        "E_CAPABILITY",
                        format!("/serviceGraph/{}/env/{name}", process.id),
                        "secret credentials are not supported by misa-svcrun yet",
                    ));
                }
            }
        }
        let readiness_fd = match process.readiness {
            Readiness::FdNewline { fd, .. } => Some(fd),
            _ => None,
        };
        Ok(Self {
            schema_version: SCHEMA.into(),
            id: process.id.clone(),
            command: process.command.clone(),
            argv: process.argv.clone(),
            cwd: process.cwd.clone(),
            env,
            identity: process.identity,
            readiness_fd,
            directories: process
                .directories
                .iter()
                .enumerate()
                .map(|(i, d)| directory(i, d))
                .collect::<Result<_>>()?,
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = misa_plan::parse_strict(bytes)?;
        let spec: Self = serde_json::from_value(value)
            .map_err(|e| Error::new("E_SCHEMA", "/", format!("not a {SCHEMA} record: {e}")))?;
        if spec.schema_version != SCHEMA {
            return Err(Error::new(
                "E_SCHEMA",
                "/schemaVersion",
                "unsupported svcrun spec",
            ));
        }
        for (field, path) in [("/command", &spec.command), ("/cwd", &spec.cwd)] {
            if !path.starts_with('/') {
                return Err(Error::new("E_SCHEMA", field, "path must be absolute"));
            }
        }
        if spec.argv.is_empty() {
            return Err(Error::new("E_SCHEMA", "/argv", "argv[0] is required"));
        }
        if let Some(fd) = spec.readiness_fd
            && !(3..=255).contains(&fd)
        {
            return Err(Error::new(
                "E_SCHEMA",
                "/readinessFd",
                "R1: descriptor must be 3..=255",
            ));
        }
        Ok(spec)
    }

    pub fn to_jcs(&self) -> Result<Vec<u8>> {
        serde_jcs::to_vec(self).map_err(|_| Error::new("E_SCHEMA", "/", "JCS serialization failed"))
    }
}
