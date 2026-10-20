//! Selected-generation verification on a fixture root: the generation that boots must
//! be exactly the one the command line names, with the init the manifest pins.
use misa_init::cmdline;
use misa_init::verify::{self, Machine};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures");
const RELEASE: &str = "6.12.34-misa-synthetic";
const INTERP: &str = "/nix/store/00000000000000000000000000000000-glibc/lib/ld-linux-x86-64.so.2";
const INIT: &str = "/nix/store/3ar38x5h8932536hvnly1axcl293a878-synthetic-dinit/bin/dinit";

/// Minimal little-endian ELF64 with one PT_INTERP program header.
fn elf(machine: u16, interp: &str) -> Vec<u8> {
    let mut b = vec![0u8; 64 + 56];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    let text = format!("{interp}\0");
    let ph = 64;
    b[ph..ph + 4].copy_from_slice(&3u32.to_le_bytes());
    b[ph + 8..ph + 16].copy_from_slice(&(120u64).to_le_bytes());
    b[ph + 32..ph + 40].copy_from_slice(&(text.len() as u64).to_le_bytes());
    b.extend_from_slice(text.as_bytes());
    b
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn put(root: &Path, path: &str, bytes: &[u8], mode: u32) {
    let host = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(host.parent().unwrap()).unwrap();
    fs::write(&host, bytes).unwrap();
    fs::set_permissions(&host, fs::Permissions::from_mode(mode)).unwrap();
}

struct Fixture {
    root: tempfile::TempDir,
    hex: String,
    cmdline: String,
}

/// A root whose generation is internally consistent; `edit` changes the manifest body
/// before its identity is computed, `init` replaces the installed init bytes.
fn fixture(edit: impl FnOnce(&mut Value), init: Option<Vec<u8>>) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let plan_bytes = fs::read(format!("{FIXTURES}/plan.json")).unwrap();
    let plan: Value = serde_json::from_slice(&plan_bytes).unwrap();
    let top = plan["host"]["topLevel"].as_str().unwrap();
    let tree = br#"{"adapter":"dinit"}"#;
    put(
        root.path(),
        &format!("{top}/init-tree/tree.json"),
        tree,
        0o444,
    );
    put(root.path(), INTERP, b"", 0o555);
    let real_init = elf(62, INTERP);
    put(
        root.path(),
        INIT,
        init.as_deref().unwrap_or(&real_init),
        0o555,
    );

    let mut generation: Value =
        serde_json::from_slice(&fs::read(format!("{FIXTURES}/generation.json")).unwrap()).unwrap();
    let body = generation.as_object_mut().unwrap();
    body.remove("generationId");
    body.insert("adapterIdentity".into(), json!(digest(tree)));
    generation["boot"]["init"]["adapterBuildId"] = json!(digest(tree));
    generation["boot"]["init"]["sha256"] = json!(digest(&real_init));
    edit(&mut generation);
    let modules = generation["boot"]["modules"]["dir"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::create_dir_all(
        root.path()
            .join(modules.trim_start_matches('/'))
            .join(RELEASE),
    )
    .unwrap();
    let id = misa_plan::identify_generation(&serde_json::to_vec(&generation).unwrap()).unwrap();
    generation["generationId"] = json!(id);
    let hex = id.trim_start_matches("sha256:").to_owned();
    let dir = format!("/var/lib/misa/generations/{hex}");
    put(
        root.path(),
        &format!("{dir}/manifest.json"),
        &serde_json::to_vec(&generation).unwrap(),
        0o444,
    );
    put(root.path(), &format!("{dir}/plan.json"), &plan_bytes, 0o444);
    let selector = &generation["boot"]["root"]["selector"];
    let cmdline = format!(
        "console=ttyS0 misa.root={}={} misa.generation={hex}",
        selector["kind"].as_str().unwrap(),
        selector["value"].as_str().unwrap()
    );
    Fixture { root, hex, cmdline }
}

fn run(f: &Fixture, cmdline: &str) -> Result<verify::Verified, misa_plan::Error> {
    let machine = Machine {
        arch: "x86_64".into(),
        release: RELEASE.into(),
    };
    verify::verify(f.root.path(), &cmdline::parse(cmdline)?, &machine)
}

fn code(f: &Fixture, cmdline: &str) -> &'static str {
    run(f, cmdline).expect_err("verification must refuse").code
}

#[test]
fn consistent_generation_is_verified_with_every_owned_check() {
    let f = fixture(|_| {}, None);
    let verified = run(&f, &f.cmdline).unwrap();
    assert_eq!(verified.generation, format!("sha256:{}", f.hex));
    assert_eq!(verified.init_path, INIT);
    assert_eq!(
        verified.checks,
        [
            "V1", "V2", "V3", "V4", "V6", "V7", "V8", "V9", "V10", "V11", "V12"
        ]
    );
    assert_eq!(verified.journal, "absent");
}

#[test]
fn edited_manifest_bytes_are_refused_as_a_hash_mismatch() {
    let f = fixture(|_| {}, None);
    let path = f
        .root
        .path()
        .join(format!("var/lib/misa/generations/{}/manifest.json", f.hex));
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["boot"]["publisher"]["titleKey"] = json!("tampered");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(code(&f, &f.cmdline), "E_BOOT_MANIFEST_HASH");
}

#[test]
fn command_line_must_name_the_manifest_it_finds() {
    let f = fixture(|_| {}, None);
    let other = fixture(
        |g| g["boot"]["publisher"]["titleKey"] = json!("other"),
        None,
    );
    // The directory exists only under the other ID: no manifest for this name.
    let missing = f.cmdline.replace(&f.hex, &other.hex);
    assert_eq!(code(&f, &missing), "E_BOOT_MANIFEST_MISSING");
    // A manifest stored under a name that is not its identity.
    let dir = f.root.path().join("var/lib/misa/generations");
    fs::rename(dir.join(&f.hex), dir.join(&other.hex)).unwrap();
    assert_eq!(code(&f, &missing), "E_BOOT_MANIFEST_HASH");
}

#[test]
fn init_must_match_its_pinned_digest_machine_and_interpreter() {
    let wrong_digest = fixture(
        |g| g["boot"]["init"]["sha256"] = json!(digest(b"some other init")),
        None,
    );
    assert_eq!(
        code(&wrong_digest, &wrong_digest.cmdline),
        "E_BOOT_INIT_INVALID"
    );

    let aarch64 = elf(183, INTERP);
    let wrong_machine = fixture(
        |g| g["boot"]["init"]["sha256"] = json!(digest(&aarch64)),
        Some(aarch64.clone()),
    );
    let error = run(&wrong_machine, &wrong_machine.cmdline).err().unwrap();
    assert_eq!(
        (error.code, error.field.as_str()),
        ("E_BOOT_INIT_INVALID", "/boot/init/elfMachine")
    );

    let orphan = elf(62, "/nix/store/00000000000000000000000000000000-gone/ld.so");
    let missing_interp = fixture(
        |g| g["boot"]["init"]["sha256"] = json!(digest(&orphan)),
        Some(orphan.clone()),
    );
    let error = run(&missing_interp, &missing_interp.cmdline).err().unwrap();
    assert!(error.message.contains("interpreter"), "{error}");
}

#[test]
fn hand_edited_root_selector_is_refused() {
    let f = fixture(|_| {}, None);
    let edited = f.cmdline.replace(
        "fsuuid=913f2e4a-2b0d-4d71-9b24-97e0c4bfa193",
        "partuuid=913f2e4a-2b0d-4d71-9b24-97e0c4bfa193",
    );
    assert_eq!(code(&f, &edited), "E_BOOT_ROOT_SELECTOR");
}

#[test]
fn closure_init_tree_must_be_the_manifest_adapter_build() {
    let f = fixture(|_| {}, None);
    let plan: Value =
        serde_json::from_slice(&fs::read(format!("{FIXTURES}/plan.json")).unwrap()).unwrap();
    let tree = f.root.path().join(format!(
        "{}/init-tree/tree.json",
        plan["host"]["topLevel"]
            .as_str()
            .unwrap()
            .trim_start_matches('/')
    ));
    fs::set_permissions(&tree, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&tree, br#"{"adapter":"other"}"#).unwrap();
    let error = run(&f, &f.cmdline).err().unwrap();
    assert_eq!(
        (error.code, error.field.as_str()),
        ("E_BOOT_INIT_INVALID", "/boot/init/adapterBuildId")
    );
}

#[test]
fn running_kernel_must_be_the_manifest_kernel() {
    let f = fixture(|_| {}, None);
    let machine = Machine {
        arch: "x86_64".into(),
        release: "6.18.55".into(),
    };
    let error = verify::verify(
        f.root.path(),
        &cmdline::parse(&f.cmdline).unwrap(),
        &machine,
    )
    .err()
    .unwrap();
    assert_eq!(error.code, "E_BOOT_KERNEL_MISMATCH");
}

#[test]
fn command_line_misa_keys_are_strict() {
    let generation = "a".repeat(64);
    let root = "misa.root=partuuid=5a3a0001-0000-4000-8000-00000000c0de";
    for bad in [
        format!("{root} misa.generation={generation} misa.unknown=1"),
        format!("{root} misa.generation={generation} misa.generation={generation}"),
        format!("{root} misa.generation={generation} misa.rescue=1"),
        format!("{root} misa.generation={}", "A".repeat(64)),
        root.to_string(),
        format!("misa.root=/dev/vda1 misa.generation={generation}"),
    ] {
        assert_eq!(
            cmdline::parse(&bad).err().unwrap().code,
            "E_BOOT_CMDLINE",
            "{bad}"
        );
    }
    let ok = cmdline::parse(&format!(
        "quiet {root} init=/x misa.wait=5 misa.generation={generation}"
    ))
    .unwrap();
    assert_eq!(
        (ok.generation.as_str(), ok.wait),
        (generation.as_str(), Some(5))
    );
}
