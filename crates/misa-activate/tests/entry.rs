//! BLS entries are derived artifacts: the same manifest, token and sequence always
//! render the same name and bytes, and the entry carries the generation it names.
use misa_activate::bls;
use serde_json::{Value, json};

const GENERATION: &str = include_str!("../../../fixtures/generation.json");

fn validated(edit: impl FnOnce(&mut Value)) -> misa_plan::ValidatedRecord {
    let mut g: Value = serde_json::from_str(GENERATION).unwrap();
    g.as_object_mut().unwrap().remove("generationId");
    edit(&mut g);
    let id = misa_plan::identify_generation(&serde_json::to_vec(&g).unwrap()).unwrap();
    g["generationId"] = json!(id);
    misa_plan::validate(
        &serde_json::to_vec(&g).unwrap(),
        Some(misa_plan::Domain::Generation),
    )
    .unwrap()
}

#[test]
fn entry_names_and_boots_exactly_its_generation() {
    let manifest = validated(|_| {});
    let id = &manifest.digest()["sha256:".len()..];
    let entry = bls::render(&manifest, 42).unwrap();
    assert_eq!(entry, bls::render(&manifest, 42).unwrap());
    assert_eq!(entry.file_name, format!("misa-a7053e98-{}.conf", &id[..12]));
    let lines: Vec<&str> = entry.content.lines().collect();
    assert_eq!(lines[3], "version 0000000042");
    // Microcode first, then main, in manifest order (BLS uses all initrds in order).
    let initrds: Vec<&str> = lines
        .iter()
        .filter(|l| l.starts_with("initrd "))
        .copied()
        .collect();
    assert_eq!(initrds.len(), 2);
    assert!(initrds[0].ends_with("/ucode.img") && initrds[1].ends_with("/initrd.img"));
    assert_eq!(
        *lines.last().unwrap(),
        format!(
            "options misa.root=fsuuid=913f2e4a-2b0d-4d71-9b24-97e0c4bfa193 console=ttyS0,115200 quiet misa.generation={id}"
        )
    );
    // Blob names are content addressed by the manifest digests.
    let kernel = manifest.value()["boot"]["kernel"]["sha256"]
        .as_str()
        .unwrap();
    assert_eq!(
        entry.blobs[0].path,
        format!(
            "/misa/a7053e985d06f8768ceacc7ecef4ef59/k-{}/linux",
            &kernel[7..39]
        )
    );
}

#[test]
fn counting_entries_carry_pre_initialised_two_digit_counters() {
    let manifest = validated(|g| {
        g["boot"]["publisher"]["selection"] = json!("counting");
        g["boot"]["publisher"]["tries"] = json!(3);
    });
    let name = bls::render(&manifest, 1).unwrap().file_name;
    assert!(name.ends_with("+03-00.conf"), "{name}");
    assert_eq!(
        bls::render(&manifest, 0).err().unwrap().code,
        "E_BOOT_PUBLISHER"
    );
}
