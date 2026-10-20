//! Dinit adapter: a pure function from a validated graph to a service directory (G11).
//!
//! Every process runs through `misa-svcrun --spec <specs>/<id>.json`; spec files live
//! in a separate immutable output so a loaded description never resolves through
//! the `/run/misa/dinit/services` symlink a later switch may swap (W5). The graph's
//! `boot` milestone is the service Dinit starts as PID 1.
use crate::capability::CapabilityReport;
use crate::graph::{Graph, Milestone, Node, Process, Readiness, Restart};
use crate::spec::SvcrunSpec;
use misa_plan::{Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Descriptor Dinit opens as the readiness pipe; misa-svcrun moves it to the service's.
pub const MANAGER_READY_FD: u32 = 4;
pub const BOOT_SERVICE: &str = "boot";

pub struct Compiled {
    /// Service description files, by service name.
    pub services: BTreeMap<String, Vec<u8>>,
    /// `misa.svcrun/v1` records, by file name.
    pub specs: BTreeMap<String, Vec<u8>>,
    /// Canonical `misa.init-tree/v1` record; its SHA-256 is the adapter build identity.
    pub tree: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TreeRecord<'a> {
    schema_version: &'static str,
    adapter: &'static str,
    capabilities: &'a CapabilityReport,
    graph_digest: String,
    svcrun: &'a str,
    specs: &'a str,
    services: BTreeMap<&'a str, String>,
    spec_files: BTreeMap<&'a str, String>,
}

fn word(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || !value.starts_with('/')
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'"' | b'\\' | b'$' | b'#'))
    {
        return Err(Error::new(
            "E_SCHEMA",
            field,
            "Dinit command words must be absolute paths without whitespace, quotes, $ or #",
        ));
    }
    Ok(())
}

fn signal(name: &str) -> Result<&'static str> {
    Ok(match name {
        "SIGTERM" => "TERM",
        "SIGINT" => "INT",
        "SIGHUP" => "HUP",
        "SIGQUIT" => "QUIT",
        _ => {
            return Err(Error::new(
                "E_SCHEMA",
                "/stop/signal",
                "unsupported stop signal",
            ));
        }
    })
}

fn edges(out: &mut String, requires: &[String], wants: &[String], after: &[String]) {
    for id in requires {
        writeln!(out, "depends-on: {id}").unwrap();
    }
    for id in wants {
        writeln!(out, "waits-for: {id}").unwrap();
    }
    for id in after {
        writeln!(out, "after: {id}").unwrap();
    }
}

fn milestone(graph: &Graph, m: &Milestone) -> String {
    let mut out = String::from("type = internal\n");
    let mut requires: Vec<String> = m.requires.clone();
    if let Some(members) = graph.targets.get(&m.id) {
        requires.extend(members.iter().cloned());
    }
    requires.sort();
    requires.dedup();
    edges(&mut out, &requires, &m.wants, &m.after);
    out
}

fn process(p: &Process, oneshot: bool, svcrun: &str, specs: &str) -> Result<String> {
    let field = |name: &str| format!("/serviceGraph/{}/{name}", p.id);
    let mut out = String::new();
    writeln!(
        out,
        "type = {}",
        if oneshot { "scripted" } else { "process" }
    )
    .unwrap();
    let ready_timeout = match p.readiness {
        Readiness::ExecStarted => None,
        Readiness::FdNewline { timeout, .. } if !oneshot => Some(timeout),
        Readiness::FdNewline { .. } => {
            return Err(Error::new(
                "E_SCHEMA",
                field("readiness"),
                "a oneshot is Ready when it exits 0; descriptor readiness applies to longruns",
            ));
        }
        Readiness::Probe { .. } => {
            return Err(Error::new(
                "E_CAPABILITY",
                field("readiness"),
                "Dinit has no qualified probe readiness",
            ));
        }
    };
    write!(out, "command = {svcrun} --spec {specs}/{}.json", p.id).unwrap();
    if let Some(timeout) = ready_timeout {
        writeln!(
            out,
            " --ready-fd {MANAGER_READY_FD}\nready-notification = pipefd:{MANAGER_READY_FD}\nstart-timeout = {timeout}"
        )
        .unwrap();
    } else {
        out.push('\n');
    }
    match p.restart {
        Restart::Never => out.push_str("restart = no\n"),
        Restart::Always => out.push_str("restart = yes\n"),
        Restart::OnFailure {
            burst,
            window,
            delay,
        } => {
            writeln!(
                out,
                "restart = on-failure\nrestart-delay = {delay}\nrestart-limit-interval = {window}\nrestart-limit-count = {burst}"
            )
            .unwrap();
        }
    }
    if p.stop.grace_period == 0 {
        return Err(Error::new(
            "E_SCHEMA",
            field("stop/gracePeriod"),
            "Dinit stop-timeout 0 means unbounded; a finite grace period is required",
        ));
    }
    writeln!(out, "stop-timeout = {}", p.stop.grace_period).unwrap();
    writeln!(out, "term-signal = {}", signal(&p.stop.signal)?).unwrap();
    if !p.stop.kill_process_group {
        out.push_str("options: signal-process-only\n");
    }
    out.push_str("working-dir = /\nlog-type = buffer\n");
    edges(&mut out, &p.requires, &p.wants, &p.after);
    Ok(out)
}

/// Name of the build record inside a compiled tree; no service may use it.
pub const TREE_RECORD: &str = "tree.json";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Compile a validated graph. `svcrun` and `specs` are the absolute store paths the
/// emitted commands name; `release` is the pinned Dinit release the report covers.
pub fn compile(
    graph_value: &serde_json::Value,
    release: &str,
    svcrun: &str,
    specs: &str,
) -> Result<Compiled> {
    word("--svcrun", svcrun)?;
    word("--specs", specs)?;
    let graph = Graph::parse(graph_value)?;
    let report = CapabilityReport::dinit(release);
    report.negotiate(&graph)?;
    match graph.node(BOOT_SERVICE) {
        Some(Node::Milestone(_)) => {}
        _ => {
            return Err(Error::new(
                "E_SCHEMA",
                "/serviceGraph/services",
                "the graph must declare the milestone `boot`, which Dinit starts as PID 1",
            ));
        }
    }
    if graph.node(TREE_RECORD).is_some() {
        return Err(Error::new(
            "E_SCHEMA",
            "/serviceGraph/services",
            "`tree.json` names the adapter build record, not a service",
        ));
    }
    let mut services = BTreeMap::new();
    let mut spec_files = BTreeMap::new();
    for node in &graph.services {
        let text = match node {
            Node::Milestone(m) => milestone(&graph, m),
            Node::Longrun(p) | Node::Oneshot(p) => {
                spec_files.insert(
                    format!("{}.json", p.id),
                    SvcrunSpec::from_process(p)?.to_jcs()?,
                );
                process(p, matches!(node, Node::Oneshot(_)), svcrun, specs)?
            }
        };
        services.insert(node.id().to_owned(), text.into_bytes());
    }
    let record = TreeRecord {
        schema_version: "misa.init-tree/v1",
        adapter: "dinit",
        capabilities: &report,
        graph_digest: Graph::digest(graph_value)?,
        svcrun,
        specs,
        services: services
            .iter()
            .map(|(name, bytes)| (name.as_str(), sha256_hex(bytes)))
            .collect(),
        spec_files: spec_files
            .iter()
            .map(|(name, bytes)| (name.as_str(), sha256_hex(bytes)))
            .collect(),
    };
    let tree = serde_jcs::to_vec(&record)
        .map_err(|_| Error::new("E_SCHEMA", "/", "JCS serialization failed"))?;
    Ok(Compiled {
        services,
        specs: spec_files,
        tree,
    })
}
