use clap::{Parser, Subcommand, ValueEnum};
use misa_plan::{Domain, Error, MAX_INPUT_BYTES, Result};
use serde_json::json;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "misa-plan",
    version,
    about = "MisaOS S0: unprivileged wire validation, not deployment authorization"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate syntax and semantic invariants; emit a receipt without trusting artifacts.
    Validate {
        file: PathBuf,
        #[arg(long, value_enum)]
        expect: Option<Expected>,
    },
    /// Validate a record and emit its exact RFC 8785 canonical bytes.
    Canonicalize {
        file: PathBuf,
        #[arg(long, value_enum)]
        expect: Option<Expected>,
    },
    /// Validate a record and print its semantic digest (generation IDs exclude their ID).
    Digest {
        file: PathBuf,
        #[arg(long, value_enum)]
        expect: Option<Expected>,
    },
    /// Canonicalize arbitrary strict JSON with Misa's bounded-integer numeric profile.
    Jcs { file: PathBuf },
    /// Validate a generation body WITHOUT generationId and compute that identity.
    GenerationId { file: PathBuf },
    /// Print the self-contained published JSON Schema for an authority domain.
    Schema {
        #[arg(value_enum)]
        domain: Expected,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Expected {
    Strata,
    Plan,
    Generation,
}

impl From<Expected> for Domain {
    fn from(value: Expected) -> Self {
        match value {
            Expected::Strata => Self::Strata,
            Expected::Plan => Self::Plan,
            Expected::Generation => Self::Generation,
        }
    }
}

fn input(file: &PathBuf) -> Result<Vec<u8>> {
    if file.as_os_str() == "-" {
        read_bounded(io::stdin().lock())
    } else {
        read_bounded(
            File::open(file).map_err(|_| Error::new("E_IO", "", "cannot open input file"))?,
        )
    }
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("E_IO", "", "cannot read input file"))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::new(
            "E_SCHEMA",
            "",
            "record exceeds the 1 MiB input limit",
        ));
    }
    Ok(bytes)
}

fn run(command: Command, output: &mut impl Write) -> Result<()> {
    let write_error = |_| Error::new("E_IO", "", "cannot write output");
    match command {
        Command::Schema { domain } => output
            .write_all(Domain::from(domain).schema().as_bytes())
            .map_err(write_error),
        Command::Jcs { file } => output
            .write_all(&misa_plan::canonicalize_json(&input(&file)?)?)
            .map_err(write_error),
        Command::GenerationId { file } => writeln!(
            output,
            "{}",
            misa_plan::identify_generation(&input(&file)?)?
        )
        .map_err(write_error),
        Command::Canonicalize { file, expect } => {
            let record = misa_plan::validate(&input(&file)?, expect.map(Into::into))?;
            output.write_all(record.canonical()).map_err(write_error)
        }
        Command::Digest { file, expect } => {
            let record = misa_plan::validate(&input(&file)?, expect.map(Into::into))?;
            writeln!(output, "{}", record.digest()).map_err(write_error)
        }
        Command::Validate { file, expect } => {
            let record = misa_plan::validate(&input(&file)?, expect.map(Into::into))?;
            let roots = record
                .value()
                .get("roots")
                .and_then(|roots| roots.as_array());
            let receipt = json!({
                "schemaVersion": record.domain().schema_version(),
                "digest": record.digest(),
                "rawDigest": record.raw_digest(),
                "validationScope": "schema-and-semantics-only",
                "artifactVerification": "not-performed",
                "rootQualifications": roots.into_iter().flatten().filter_map(|root| {
                    root.get("qualification").map(|qualification| json!({"name": root["name"], "qualification": qualification}))
                }).collect::<Vec<_>>(),
            });
            writeln!(output, "{receipt}").map_err(write_error)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut output = io::stdout().lock();
    match run(cli.command, &mut output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let diagnostic =
                json!({"code": error.code, "field": error.field, "message": error.message});
            let _ = writeln!(io::stderr().lock(), "{diagnostic}");
            ExitCode::from(2)
        }
    }
}
