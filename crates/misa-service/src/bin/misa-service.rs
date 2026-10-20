use clap::{Parser, Subcommand, ValueEnum};
use misa_plan::{Error, Result};
use std::{
    fs, io::Write, os::unix::fs::PermissionsExt, path::Path, path::PathBuf, process::ExitCode,
};

#[derive(Parser)]
#[command(about = "Compile a MisaOS service graph for an init adapter")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Adapter {
    Dinit,
}

#[derive(Subcommand)]
enum Command {
    /// Validate and negotiate a graph without emitting anything.
    Check {
        #[arg(long)]
        graph: PathBuf,
        #[arg(long, value_enum)]
        adapter: Adapter,
        /// Pinned upstream release the capability report covers.
        #[arg(long)]
        release: String,
    },
    /// Emit the adapter's service tree and the misa-svcrun spec files.
    Compile {
        #[arg(long)]
        graph: PathBuf,
        #[arg(long, value_enum)]
        adapter: Adapter,
        #[arg(long)]
        release: String,
        /// Absolute path of the misa-svcrun executable the services name.
        #[arg(long)]
        svcrun: String,
        /// New directory for the service tree; its tree.json identifies the build.
        #[arg(long)]
        tree_out: PathBuf,
        /// New directory for spec files; the emitted commands name this path.
        #[arg(long)]
        specs_out: PathBuf,
    },
}

fn read_graph(path: &Path) -> Result<serde_json::Value> {
    let bytes = fs::read(path)
        .map_err(|e| Error::new("E_STATE", path.display().to_string(), e.to_string()))?;
    misa_plan::parse_strict(&bytes)
}

fn write_tree(dir: &Path, files: impl IntoIterator<Item = (String, Vec<u8>)>) -> Result<()> {
    let io = |e: std::io::Error| Error::new("E_STATE", dir.display().to_string(), e.to_string());
    fs::create_dir(dir).map_err(io)?;
    for (name, bytes) in files {
        let path = dir.join(&name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(io)?;
        file.write_all(&bytes).map_err(io)?;
        file.set_permissions(fs::Permissions::from_mode(0o444))
            .map_err(io)?;
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).map_err(io)
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Check {
            graph,
            adapter: Adapter::Dinit,
            release,
        } => {
            let graph = misa_service::graph::Graph::parse(&read_graph(&graph)?)?;
            misa_service::capability::CapabilityReport::dinit(&release).negotiate(&graph)
        }
        Command::Compile {
            graph,
            adapter: Adapter::Dinit,
            release,
            svcrun,
            tree_out,
            specs_out,
        } => {
            let specs = specs_out
                .to_str()
                .ok_or_else(|| Error::new("E_SCHEMA", "--specs-out", "path is not UTF-8"))?;
            let compiled =
                misa_service::dinit::compile(&read_graph(&graph)?, &release, &svcrun, specs)?;
            write_tree(&specs_out, compiled.specs)?;
            let mut files: Vec<_> = compiled.services.into_iter().collect();
            files.push(("tree.json".into(), compiled.tree));
            write_tree(&tree_out, files)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"code": error.code, "field": error.field, "message": error.message})
            );
            ExitCode::from(2)
        }
    }
}
