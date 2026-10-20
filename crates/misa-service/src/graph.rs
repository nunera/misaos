//! Typed view of a validated `misa.plan/v1` `serviceGraph`.
//!
//! [`Graph::parse`] runs the plan's closed schema and graph rules (G9: cycles with a
//! witness, duplicate IDs, missing targets, system-requires-user, memberless
//! milestones) through `misa-plan` before any adapter sees the graph.
use misa_plan::{Error, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Graph {
    pub services: Vec<Node>,
    pub targets: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Node {
    Milestone(Milestone),
    Longrun(Process),
    Oneshot(Process),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Milestone {
    pub id: String,
    pub scope: Scope,
    pub requires: Vec<String>,
    pub wants: Vec<String>,
    pub after: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    pub id: String,
    pub scope: Scope,
    pub requires: Vec<String>,
    pub wants: Vec<String>,
    pub after: Vec<String>,
    pub command: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, EnvValue>,
    pub identity: Identity,
    pub readiness: Readiness,
    pub restart: Restart,
    pub stop: Stop,
    pub directories: Vec<Directory>,
    pub sockets: Vec<Value>,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub backend_options: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Scope {
    System,
    User { uid: u32 },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EnvValue {
    Literal {
        value: String,
    },
    Secret {
        #[serde(rename = "secretId")]
        secret_id: String,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Readiness {
    ExecStarted,
    FdNewline {
        fd: u32,
        timeout: u32,
    },
    Probe {
        program: String,
        args: Vec<String>,
        timeout: u32,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Restart {
    Never,
    Always,
    OnFailure { burst: u32, window: u32, delay: u32 },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stop {
    pub signal: String,
    pub grace_period: u32,
    pub kill_process_group: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub path: String,
    pub owner: Identity,
    pub mode: String,
    pub lifetime: String,
}

impl Node {
    pub fn id(&self) -> &str {
        match self {
            Self::Milestone(m) => &m.id,
            Self::Longrun(p) | Self::Oneshot(p) => &p.id,
        }
    }
}

impl Graph {
    /// Validate with the plan's graph rules, then type the result.
    pub fn parse(graph: &Value) -> Result<Self> {
        misa_plan::validate_service_graph(graph)?;
        serde_json::from_value(graph.clone()).map_err(|_| {
            Error::new(
                "E_SCHEMA",
                "/serviceGraph",
                "graph does not match its typed model",
            )
        })
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.services.iter().find(|node| node.id() == id)
    }

    /// `sha256(JCS(graph))`: the graph identity recorded beside the compiled tree (G11).
    pub fn digest(graph: &Value) -> Result<String> {
        let bytes = serde_jcs::to_vec(graph)
            .map_err(|_| Error::new("E_SCHEMA", "/serviceGraph", "JCS serialization failed"))?;
        Ok(misa_plan::hash_bytes(&bytes))
    }
}
