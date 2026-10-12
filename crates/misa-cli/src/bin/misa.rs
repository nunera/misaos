use clap::{Parser, Subcommand, ValueEnum};
use misa_image::{Error, Result, Store, Tools, model, resolve, trust};
use serde::Serialize;
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "misa",
    version,
    about = "Unprivileged MisaOS OCI admission and retain-all storage; no host activation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Resolve, approve, import and verify foreign image roots.
    Strata {
        #[command(subcommand)]
        command: Strata,
    },
    /// Manage explicit local image-admission keys, not publisher identities.
    Trust {
        #[command(subcommand)]
        command: Trust,
    },
    /// Print the closed JSON Schema for a new import wire record.
    Schema {
        #[arg(value_enum)]
        domain: Schema,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Schema {
    Lock,
    Approval,
    PublicKey,
}

#[derive(Subcommand)]
enum Trust {
    /// Create a new 0700 directory containing a 0600 secret key and public key.
    Keygen {
        #[arg(long)]
        directory: PathBuf,
    },
}

#[derive(Subcommand)]
enum Strata {
    /// Resolve an explicit tag/digest into an unsigned platform-specific candidate lock.
    Resolve {
        #[arg(long)]
        image: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        platform: String,
        /// Operator declaration; runtime ELF/ABI qualification is a later gate.
        #[arg(long, value_parser = ["glibc", "musl"])]
        libc: String,
        /// Write a new canonical lock file; never overwrite an existing lock.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Sign the entire reviewed lock as local admission, NOT as its upstream publisher.
    Approve {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        secret_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify local approval and image bytes, materialize safely, retain indefinitely.
    Import {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long)]
        name: String,
        /// Caller-owned private store. This command never chooses a system location.
        #[arg(long)]
        store: PathBuf,
        /// Import from a local OCI layout without contacting any registry.
        #[arg(long, conflicts_with = "offline")]
        from_layout: Option<PathBuf>,
        /// Reimport exclusively from this store's retained OCI blobs.
        #[arg(long)]
        offline: bool,
    },
    /// Report all retained roots and disk-byte growth; does not verify contents.
    List {
        #[arg(long)]
        store: PathBuf,
    },
    /// Reverify retained approval, OCI graph and materialized tree without network/repair.
    Doctor {
        #[arg(long)]
        store: PathBuf,
    },
}

fn read_record(path: &Path, secret: bool) -> Result<Vec<u8>> {
    let reader: Box<dyn Read> = if path.as_os_str() == "-" && !secret {
        Box::new(io::stdin().lock())
    } else {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)
            .map_err(|_| {
                Error::new(
                    "E_IO",
                    "input",
                    "cannot open regular input file without following a symlink",
                )
            })?;
        let metadata = file
            .metadata()
            .map_err(|_| Error::new("E_IO", "input", "cannot inspect input file"))?;
        if !metadata.is_file()
            || (secret
                && (metadata.mode() & 0o077 != 0
                    || metadata.uid() != rustix::process::geteuid().as_raw()))
        {
            return Err(Error::new(
                "E_TRUST",
                "input",
                "secret keys must be caller-owned regular files with no group/other permissions",
            ));
        }
        Box::new(file)
    };
    let mut bytes = Vec::new();
    reader
        .take(misa_plan::MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("E_IO", "input", "cannot read input record"))?;
    if bytes.len() > misa_plan::MAX_INPUT_BYTES {
        return Err(Error::new(
            "E_SCHEMA",
            "input",
            "record exceeds the 1 MiB limit",
        ));
    }
    Ok(bytes)
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value)
        .map_err(|_| Error::new("E_SCHEMA", "output", "cannot canonicalize output record"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| {
            Error::new(
                "E_IO",
                "output",
                "cannot create output; choose a new file in an existing directory",
            )
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::new("E_IO", "output", "cannot persist output file"))?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error::new("E_IO", "output", "cannot persist output directory"))
}

fn emit(value: &impl Serialize, output: Option<&Path>) -> Result<()> {
    let bytes = canonical(value)?;
    if let Some(path) = output {
        write_new(path, &bytes)
    } else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(&bytes)
            .and_then(|()| stdout.write_all(b"\n"))
            .map_err(|_| Error::new("E_IO", "output", "cannot write output"))
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Schema { domain } => {
            let schema = match domain {
                Schema::Lock => include_str!("../../../../schemas/misa.lock-v1.schema.json"),
                Schema::Approval => {
                    include_str!("../../../../schemas/misa.approval-v1.schema.json")
                }
                Schema::PublicKey => {
                    include_str!("../../../../schemas/misa.ed25519-public-v1.schema.json")
                }
            };
            io::stdout()
                .lock()
                .write_all(schema.as_bytes())
                .map_err(|_| Error::new("E_IO", "output", "cannot write schema"))
        }
        Command::Trust {
            command: Trust::Keygen { directory },
        } => {
            let (secret, public) = trust::generate_keypair()?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|_| {
                    Error::new(
                        "E_IO",
                        "keygen",
                        "choose a new key directory under an existing parent",
                    )
                })?;
            write_new(&directory.join("secret.json"), &canonical(&secret)?)?;
            write_new(&directory.join("public.json"), &canonical(&public)?)?;
            emit(
                &json!({"authority":"local-image-admission", "keyId":trust::key_id(&public)?,
                "secretKey":directory.join("secret.json"),"publicKey":directory.join("public.json")}),
                None,
            )
        }
        Command::Strata { command } => match command {
            Strata::Resolve {
                image,
                name,
                platform,
                libc,
                output,
            } => {
                let lock = resolve::resolve(&image, &platform, &name, &libc, &Tools::from_env()?)?;
                emit(&lock, output.as_deref())
            }
            Strata::Approve {
                lock,
                secret_key,
                output,
            } => {
                let lock = model::parse_lock(&read_record(&lock, false)?)?;
                let secret = trust::parse_secret_key(&read_record(&secret_key, true)?)?;
                emit(&trust::approve(&lock, &secret)?, output.as_deref())
            }
            Strata::Import {
                lock,
                approval,
                trusted_key,
                name,
                store,
                from_layout,
                offline,
            } => {
                let authorized = trust::verify_approval(
                    model::parse_lock(&read_record(&lock, false)?)?,
                    trust::parse_approval(&read_record(&approval, false)?)?,
                    trust::parse_public_key(&read_record(&trusted_key, false)?)?,
                )?;
                let locked = authorized.lock().strata.get(&name).ok_or_else(|| {
                    Error::new("E_LOCK", "stratum", "stratum is not in the approved lock")
                })?;
                let tools = Tools::from_env()?;
                let retained = Store::open(&store)?;
                let temporary;
                let source = if let Some(path) = from_layout {
                    path
                } else if offline {
                    store.join("oci")
                } else {
                    temporary = tempfile::tempdir().map_err(|_| {
                        Error::new("E_IO", "fetch", "cannot create private download staging")
                    })?;
                    let path = temporary.path().join("oci");
                    resolve::fetch(&authorized, &name, &path, &tools)?;
                    path
                };
                let receipt = retained.import(&authorized, &name, &source, &tools)?;
                let receipt_digest = misa_plan::hash_bytes(&canonical(&receipt)?);
                emit(
                    &json!({
                        "receipt":receipt,
                        "receiptDigest":receipt_digest,
                        "admissionAuthority":"local-image-admission",
                        "publisherVerification":"not-performed",
                        "launchQualification":"not-performed",
                        "verifiedRoot":{
                            "name":name,"platform":authorized.lock().target_platform,
                            "libcFamily":locked.libc_family,"digest":locked.image.digest,"sourceLockKey":name,
                            "sealedPath":{"kind":"oci","layout":receipt.oci_layout,"manifest":locked.image.digest},
                            "composeReceiptDigest":receipt_digest,"qualification":"R1"
                        }
                    }),
                    None,
                )
            }
            Strata::List { store } => emit(&Store::open(&store)?.list()?, None),
            Strata::Doctor { store } => {
                emit(&Store::open(&store)?.doctor(&Tools::from_env()?)?, None)
            }
        },
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                json!({"code":error.code,"field":error.field,"message":error.message})
            );
            ExitCode::from(2)
        }
    }
}
