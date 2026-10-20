use clap::Parser;
use misa_service::{spec::SvcrunSpec, svcrun};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(about = "Launch one MisaOS service from its misa.svcrun/v1 spec")]
struct Cli {
    #[arg(long)]
    spec: PathBuf,
    /// Readiness descriptor opened by the service manager.
    #[arg(long)]
    ready_fd: Option<u32>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let error = match std::fs::read(&cli.spec)
        .map_err(|e| {
            misa_plan::Error::new("E_STATE", cli.spec.display().to_string(), e.to_string())
        })
        .and_then(|bytes| SvcrunSpec::parse(&bytes))
    {
        Ok(spec) => svcrun::launch(&spec, cli.ready_fd),
        Err(error) => error,
    };
    eprintln!(
        "misa-svcrun: {}",
        serde_json::json!({"code": error.code, "field": error.field, "message": error.message})
    );
    ExitCode::from(111)
}
