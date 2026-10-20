use clap::{Parser, Subcommand};
use misa_activate::{bls, efi};
use misa_plan::{Domain, Error, Result};
use std::{fs, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(about = "MisaOS boot-entry publication and loader probing")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the BLS entry a generation renders to, without writing anything.
    Render {
        #[arg(long)]
        generation: PathBuf,
        #[arg(long)]
        sequence: u64,
    },
    /// Copy a generation's kernel and initrd parts to a boot partition, then commit its entry.
    Publish {
        /// Mounted boot partition ($BOOT).
        #[arg(long)]
        boot: PathBuf,
        #[arg(long)]
        generation: PathBuf,
        #[arg(long)]
        sequence: u64,
    },
    /// Report the running loader's Boot Loader Interface variables.
    LoaderInfo {
        #[arg(long, default_value = "/sys/firmware/efi/efivars")]
        efivars: PathBuf,
    },
}

fn manifest(path: &PathBuf) -> Result<misa_plan::ValidatedRecord> {
    let bytes = fs::read(path)
        .map_err(|e| Error::new("E_STATE", path.display().to_string(), e.to_string()))?;
    misa_plan::validate(&bytes, Some(Domain::Generation))
}

fn json<T: serde::Serialize>(value: &T) -> Result<()> {
    let bytes = serde_jcs::to_vec(value).map_err(|e| Error::new("E_STATE", "/", e.to_string()))?;
    println!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Render {
            generation,
            sequence,
        } => {
            let entry = bls::render(&manifest(&generation)?, sequence)?;
            println!("# {}", entry.file_name);
            print!("{}", entry.content);
            Ok(())
        }
        Command::Publish {
            boot,
            generation,
            sequence,
        } => {
            let manifest = manifest(&generation)?;
            let entry = bls::render(&manifest, sequence)?;
            json(&bls::publish(&boot, &manifest, &entry, sequence)?)
        }
        Command::LoaderInfo { efivars } => json(&efi::read(&efivars)?),
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
