//! Adapter capability reports and graph negotiation (Chapter 13, N1-N4).
//!
//! N1: an adapter states one level per capability with the conformance vectors that
//! are its evidence. N2: a level is only meaningful once those vectors pass on the
//! exact upstream release; the gate that runs them is the S3 VM test, and a vector
//! that has not been run is reported as `?` there, never as a pass. N3: the required
//! set is the graph-implied set, and every shortfall is reported in one
//! `E_CAPABILITY`. N4: helpers (here `misa-svcrun`) may provide `ready-fd` only.
use crate::graph::{EnvValue, Graph, Node, Readiness, Restart, Scope};
use misa_plan::{Error, Result};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Native,
    Helper,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub capability: &'static str,
    pub level: Level,
    pub evidence: &'static [&'static str],
    pub caveats: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Upstream {
    pub name: &'static str,
    pub release: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityReport {
    pub schema_version: &'static str,
    pub adapter: &'static str,
    pub upstream: Upstream,
    pub entries: Vec<Entry>,
}

impl CapabilityReport {
    /// The Dinit adapter's claims for one pinned release.
    pub fn dinit(release: &str) -> Self {
        let entries = vec![
            Entry {
                capability: "credentials",
                level: Level::None,
                evidence: &[],
                caveats: "secret environment values need misa-svcrun credential descriptors (INIT-12), not yet implemented",
            },
            Entry {
                capability: "oneshot",
                level: Level::Native,
                evidence: &[],
                caveats: "type = scripted; Ready after exit 0. INIT-04 (exactly once) is not run yet",
            },
            Entry {
                capability: "ready-fd",
                level: Level::Helper,
                evidence: &[
                    "V-RDY-01", "V-RDY-02", "V-RDY-03", "V-RDY-04", "V-RDY-05", "V-RDY-06",
                ],
                caveats: "ready-notification = pipefd:4; misa-svcrun moves descriptor 4 onto the declared one. Start timeout sends SIGINT to the process group, not the declared stop signal. dinitctl is-failed reports an exit before readiness as STOPPED, not failed; the console reports [FAILED]",
            },
            Entry {
                capability: "readiness-probe",
                level: Level::None,
                evidence: &[],
                caveats: "no declared equivalence for probe readiness",
            },
            Entry {
                capability: "restart-burst",
                level: Level::Native,
                evidence: &["V-RST-01", "V-RST-02", "V-RST-03", "V-RST-04"],
                caveats: "restart-limit-count/interval; Dinit treats HUP, INT, USR1, USR2 and TERM as clean termination",
            },
            Entry {
                capability: "socket-activation",
                level: Level::None,
                evidence: &[],
                caveats: "never satisfied by a helper (N4)",
            },
            Entry {
                capability: "stop-process-only",
                level: Level::Native,
                evidence: &[],
                caveats: "options: signal-process-only; no conformance vector run yet",
            },
            Entry {
                capability: "user-session",
                level: Level::None,
                evidence: &[],
                caveats: "no session provider at S3a; headless host",
            },
            Entry {
                capability: "weak-dependency",
                level: Level::Native,
                evidence: &["V-GR-05"],
                caveats: "waits-for",
            },
        ];
        Self {
            schema_version: "misa.capability-report/v1",
            adapter: "dinit",
            upstream: Upstream {
                name: "dinit",
                release: release.to_owned(),
            },
            entries,
        }
    }

    fn level(&self, capability: &str) -> Level {
        self.entries
            .iter()
            .find(|entry| entry.capability == capability)
            .map_or(Level::None, |entry| entry.level)
    }

    /// N3: compute the graph-implied capability set and reject every shortfall at once.
    pub fn negotiate(&self, graph: &Graph) -> Result<()> {
        let mut missing = Vec::new();
        for node in &graph.services {
            let mut need = |field: &str, capability: &'static str| {
                let level = self.level(capability);
                if level == Level::None {
                    missing.push(format!("({}, {field}, {capability}, none)", node.id()));
                }
            };
            let (scope, wants) = match node {
                Node::Milestone(m) => (&m.scope, &m.wants),
                Node::Longrun(p) | Node::Oneshot(p) => (&p.scope, &p.wants),
            };
            if matches!(scope, Scope::User { .. }) {
                need("scope", "user-session");
            }
            if !wants.is_empty() {
                need("wants", "weak-dependency");
            }
            let process = match node {
                Node::Milestone(_) => continue,
                Node::Oneshot(p) => {
                    need("kind", "oneshot");
                    p
                }
                Node::Longrun(p) => p,
            };
            match process.readiness {
                Readiness::ExecStarted => {}
                Readiness::FdNewline { .. } => need("readiness", "ready-fd"),
                Readiness::Probe { .. } => need("readiness", "readiness-probe"),
            }
            if matches!(process.restart, Restart::OnFailure { .. }) {
                need("restart", "restart-burst");
            }
            if !process.stop.kill_process_group {
                need("stop", "stop-process-only");
            }
            if !process.sockets.is_empty() {
                need("sockets", "socket-activation");
            }
            if process
                .env
                .values()
                .any(|value| matches!(value, EnvValue::Secret { .. }))
            {
                need("env", "credentials");
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Error::new(
                "E_CAPABILITY",
                "/serviceGraph",
                format!(
                    "{}@{} cannot provide: {}",
                    self.adapter,
                    self.upstream.release,
                    missing.join(" ")
                ),
            ))
        }
    }
}
