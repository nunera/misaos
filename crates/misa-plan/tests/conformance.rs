use misa_plan::{
    Domain, MAX_INPUT_BYTES, canonicalize_json, hash_bytes, identify_generation, parse_strict,
    validate,
};
use serde_json::{Value, json};

const STRATA: &[u8] = include_bytes!("../../../fixtures/strata.json");
const PLAN: &[u8] = include_bytes!("../../../fixtures/plan.json");
const GENERATION: &[u8] = include_bytes!("../../../fixtures/generation.json");
const BODY: &[u8] = include_bytes!("../../../fixtures/generation-body.json");

fn fixture(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
fn checked(value: &Value) -> misa_plan::Result<misa_plan::ValidatedRecord> {
    validate(&serde_json::to_vec(value).unwrap(), None)
}
fn rejects(value: &Value, code: &str) -> misa_plan::Error {
    let error = checked(value).expect_err("invalid record accepted");
    assert_eq!(error.code, code, "{error}");
    error
}
fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn byte_level_golden_vectors() {
    let fixtures: Value =
        serde_json::from_slice(include_bytes!("../../../fixtures/wire.json")).unwrap();
    for vector in fixtures["vectors"].as_array().unwrap() {
        let input = unhex(vector["sourceHex"].as_str().unwrap());
        if let Some(expected) = vector.get("canonicalHex") {
            let actual =
                canonicalize_json(&input).unwrap_or_else(|e| panic!("{}: {e}", vector["name"]));
            assert_eq!(
                actual,
                unhex(expected.as_str().unwrap()),
                "{}",
                vector["name"]
            );
            assert_eq!(hash_bytes(&actual), vector["digest"].as_str().unwrap());
        } else {
            let error = canonicalize_json(&input).expect_err(vector["name"].as_str().unwrap());
            assert_eq!(error.code, vector["code"]);
            assert_eq!(error.field, vector["field"]);
        }
    }
}

#[test]
fn authority_domains_cannot_be_substituted() {
    for (bytes, domain) in [
        (STRATA, Domain::Strata),
        (PLAN, Domain::Plan),
        (GENERATION, Domain::Generation),
    ] {
        let record = validate(bytes, Some(domain)).unwrap();
        assert_eq!(record.domain(), domain);
        for other in [Domain::Strata, Domain::Plan, Domain::Generation] {
            if domain != other {
                assert_eq!(
                    validate(bytes, Some(other)).unwrap_err().field,
                    "/schemaVersion"
                );
            }
        }
    }
    let mut spoofed = fixture(STRATA);
    spoofed["schemaVersion"] = json!("misa.plan/v1");
    rejects(&spoofed, "E_SCHEMA");
}

#[test]
fn every_operation_object_is_closed() {
    fn inject(bytes: &[u8], value: &Value, pointer: &str) {
        if let Value::Object(fields) = value {
            // These are deliberately open maps, not operation objects.
            let is_map = matches!(
                pointer.rsplit('/').next().unwrap_or(""),
                "annotations" | "env" | "targets" | "imagePublishers" | "repoKeys"
            );
            if !is_map {
                let mut mutated = fixture(bytes);
                mutated
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("unexpectedOperation".into(), json!(true));
                rejects(&mutated, "E_SCHEMA");
            }
            for (key, child) in fields {
                inject(
                    bytes,
                    child,
                    &format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
                );
            }
        } else if let Value::Array(items) = value {
            for (i, child) in items.iter().enumerate() {
                inject(bytes, child, &format!("{pointer}/{i}"));
            }
        }
    }
    for bytes in [STRATA, PLAN, GENERATION] {
        inject(bytes, &fixture(bytes), "");
    }
}

#[test]
fn canonical_identity_preserves_arrays_and_unicode() {
    let base = validate(STRATA, None).unwrap();
    let pretty = serde_json::to_vec_pretty(base.value()).unwrap();
    let reordered = validate(&pretty, None).unwrap();
    assert_eq!(base.digest(), reordered.digest());
    assert_ne!(base.raw_digest(), reordered.raw_digest());
    let mut ordered = fixture(STRATA);
    ordered["exports"][0]["argv"] = json!(["z", "a", "a"]);
    let accepted = checked(&ordered).unwrap();
    assert_eq!(
        accepted.value()["exports"][0]["argv"],
        json!(["z", "a", "a"])
    );
    ordered["exports"][0]["argv"] = json!(["a", "z", "a"]);
    assert_ne!(accepted.digest(), checked(&ordered).unwrap().digest());
    ordered["annotations"]["label"] = json!("é");
    let composed = checked(&ordered).unwrap();
    ordered["annotations"]["label"] = json!("e\u{301}");
    assert_ne!(composed.digest(), checked(&ordered).unwrap().digest());
}

#[test]
fn generation_hash_excludes_derived_id_and_binds_body() {
    let record = validate(GENERATION, None).unwrap();
    assert_eq!(record.digest(), identify_generation(BODY).unwrap());
    assert_eq!(
        record.value()["planDigest"],
        validate(PLAN, None).unwrap().digest()
    );
    assert_ne!(record.digest(), hash_bytes(record.canonical()));
    let mut generation = fixture(GENERATION);
    generation["machineId"] = json!("0123456789abcdef0123456789abcdef");
    rejects(&generation, "E_LOCK");
    generation.as_object_mut().unwrap().remove("generationId");
    let id = identify_generation(&serde_json::to_vec(&generation).unwrap()).unwrap();
    assert_ne!(id, record.digest());
    generation["generationId"] = json!(id);
    assert_eq!(checked(&generation).unwrap().digest(), id);
    assert_eq!(
        identify_generation(GENERATION).unwrap_err().field,
        "/generationId"
    );
    assert!(identify_generation(b"{}").is_err());
}

#[test]
fn path_and_identifier_boundaries_fail_closed() {
    for path in [
        "relative",
        "/usr/../bin/sh",
        "/usr/./bin/sh",
        "/usr//bin/sh",
        "/usr/bin/",
        "/usr/\0/bin",
    ] {
        let mut value = fixture(STRATA);
        value["exports"][0]["program"] = json!(path);
        rejects(&value, "E_SCHEMA");
    }
    // A newline is a literal Linux filename byte, not a separator or normalization.
    let mut literal = fixture(STRATA);
    literal["exports"][0]["program"] = json!("/usr/..\n");
    assert_eq!(
        checked(&literal).unwrap().value()["exports"][0]["program"],
        "/usr/..\n"
    );
    for bad_id in ["Debian", "debian\n", "débian", "a/../../root"] {
        let mut value = fixture(STRATA);
        value["roots"][0]["name"] = json!(bad_id);
        rejects(&value, "E_SCHEMA");
    }
    let mut value = fixture(STRATA);
    value["roots"][0]["digest"] = json!("sha256:1234");
    rejects(&value, "E_SCHEMA");
    value["roots"][0]["digest"] = json!(format!("sha256:{}", "A".repeat(64)));
    rejects(&value, "E_SCHEMA");
}

#[test]
fn unknown_capabilities_and_unqualified_collection_are_rejected() {
    let mut value = fixture(STRATA);
    value["requiredFeatures"] = json!(["boot.uki/v1"]);
    assert_eq!(rejects(&value, "E_CAPABILITY").field, "/requiredFeatures");
    value["requiredFeatures"] = json!([]);
    value["foreignStorage"] = json!({"mode":"leased-gc", "minRetainSeconds":"60", "brokerPolicyDigest":hash_bytes(b"synthetic-policy")});
    assert_eq!(
        rejects(&value, "E_CAPABILITY").field,
        "/foreignStorage/mode"
    );
    value["foreignStorage"]
        .as_object_mut()
        .unwrap()
        .remove("brokerPolicyDigest");
    rejects(&value, "E_SCHEMA");
}

#[test]
fn root_and_export_references_cannot_be_forged() {
    let mut value = fixture(STRATA);
    value["exports"][0]["root"] = json!(hash_bytes(b"undeclared-root"));
    rejects(&value, "E_LOCK");
    value = fixture(STRATA);
    value["roots"][0]["sealedPath"]["manifest"] = json!(hash_bytes(b"different-manifest"));
    rejects(&value, "E_LOCK");
    value = fixture(STRATA);
    value["exports"][0]["grants"] = json!(["absent"]);
    rejects(&value, "E_SCHEMA");
    value = fixture(STRATA);
    let mut duplicate = value["exports"][0].clone();
    duplicate["id"] = json!("z-other-id");
    value["exports"].as_array_mut().unwrap().push(duplicate);
    rejects(&value, "E_PATH_OWNER");
}

#[test]
fn ownership_uses_component_boundaries() {
    let mut value = fixture(STRATA);
    let mut second = value["hostGrants"][0].clone();
    second["id"] = json!("z-workspace");
    second["target"] = json!("/workspaced");
    value["hostGrants"].as_array_mut().unwrap().push(second);
    assert_eq!(
        checked(&value).unwrap().value()["hostGrants"][1]["target"],
        "/workspaced"
    );
    value["hostGrants"][1]["target"] = json!("/workspace/private");
    rejects(&value, "E_PATH_OWNER");
    value["hostGrants"][1]["target"] = json!("/usr/bin");
    rejects(&value, "E_PATH_OWNER");
    value = fixture(STRATA);
    value["hostGrants"][0]["source"] = json!("/etc");
    rejects(&value, "E_PATH_OWNER");
}

#[test]
fn set_order_and_duplicate_identity_are_not_silently_normalized() {
    let mut value = fixture(PLAN);
    value["serviceGraph"]["services"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    rejects(&value, "E_SCHEMA");
    value = fixture(PLAN);
    value["serviceGraph"]["services"][2]["id"] = json!("log-sink");
    rejects(&value, "E_SCHEMA");
    value = fixture(PLAN);
    value["serviceGraph"]["services"][0]["requires"] = json!(["worker", "log-sink"]);
    rejects(&value, "E_SCHEMA");
}

#[test]
fn graph_rejects_hard_cycles_but_not_wants_cycles() {
    let mut value = fixture(PLAN);
    value["serviceGraph"]["services"][1]["after"] = json!(["worker"]);
    let error = rejects(&value, "E_SCHEMA");
    assert_eq!(error.field, "/serviceGraph");
    assert!(error.message.contains("log-sink -> worker -> log-sink"));
    value["serviceGraph"]["services"][1]["after"] = json!([]);
    value["serviceGraph"]["services"][1]["wants"] = json!(["worker"]);
    value["serviceGraph"]["services"][2]["requires"] = json!([]);
    value["serviceGraph"]["services"][2]["wants"] = json!(["log-sink"]);
    assert_eq!(
        checked(&value).unwrap().value()["serviceGraph"]["services"][1]["wants"],
        json!(["worker"])
    );
    value["serviceGraph"]["services"][1]["wants"] = json!(["missing"]);
    rejects(&value, "E_SCHEMA");
}

#[test]
fn target_members_participate_in_ordering_and_scope_checks() {
    let mut value = fixture(PLAN);
    value["serviceGraph"]["services"][0]["requires"] = json!([]);
    value["serviceGraph"]["services"][1]["requires"] = json!(["base"]);
    assert_eq!(rejects(&value, "E_SCHEMA").field, "/serviceGraph");
    value = fixture(PLAN);
    value["serviceGraph"]["services"][2]["scope"] = json!({"kind":"user", "uid":1000});
    rejects(&value, "E_SCHEMA");
}

#[test]
fn providers_are_exclusive_closed_and_transitive() {
    let mut value = fixture(PLAN);
    value["providers"][0]["requires"] = json!(["log.sink/v1"]);
    assert_eq!(rejects(&value, "E_SCHEMA").field, "/providers");
    value["providers"][0]["requires"] = json!(["network.online/v1"]);
    rejects(&value, "E_CAPABILITY");
    value = fixture(PLAN);
    let mut provider = value["providers"][0].clone();
    provider["id"] = json!("worker");
    value["providers"].as_array_mut().unwrap().push(provider);
    rejects(&value, "E_CAPABILITY");
}

#[test]
fn trust_threshold_counts_distinct_material_not_key_labels() {
    let mut value = fixture(STRATA);
    let key = value["trust"]["nixSubstituters"][0]["publicKeys"][0].clone();
    value["trust"]["approvers"] = json!({"mode":"signed-by", "keys":[key], "threshold":2});
    rejects(&value, "E_TRUST");
    let mut alias = value["trust"]["approvers"]["keys"][0].clone();
    alias["keyId"] = json!("z-alias");
    value["trust"]["approvers"]["keys"]
        .as_array_mut()
        .unwrap()
        .push(alias);
    rejects(&value, "E_TRUST");
    value = fixture(STRATA);
    value["trust"]["imagePublishers"]["debian"][0]["validUntil"] =
        value["trust"]["imagePublishers"]["debian"][0]["validFrom"].clone();
    rejects(&value, "E_TRUST");
}

#[test]
fn boot_cross_field_invariants_are_checked_before_identity() {
    for (path, replacement, code) in [
        ("/boot/init/elfMachine", json!(183), "E_ABI"),
        ("/boot/modules/uname", json!("wrong-kernel"), "E_SCHEMA"),
        ("/boot/root/mountFlags", json!(["ro", "rw"]), "E_SCHEMA"),
        (
            "/boot/health/bless/requires",
            json!(["network"]),
            "E_SCHEMA",
        ),
        (
            "/adapterIdentity",
            json!(hash_bytes(b"wrong-adapter")),
            "E_SCHEMA",
        ),
    ] {
        let mut value = fixture(GENERATION);
        *value.pointer_mut(path).unwrap() = replacement;
        rejects(&value, code);
    }
    let mut value = fixture(GENERATION);
    value["boot"]["initrd"]["parts"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    rejects(&value, "E_SCHEMA");
    value = fixture(GENERATION);
    value["boot"]["cmdline"]["template"]
        .as_array_mut()
        .unwrap()
        .push(json!("misa.generation=forbidden"));
    rejects(&value, "E_SCHEMA");
}

#[test]
fn byte_counts_preserve_u64_without_float_conversion() {
    let mut body = fixture(BODY);
    body["boot"]["kernel"]["size"] = json!("18446744073709551615");
    let id = identify_generation(&serde_json::to_vec(&body).unwrap()).unwrap();
    body["generationId"] = json!(id);
    assert_eq!(
        checked(&body).unwrap().value()["boot"]["kernel"]["size"],
        "18446744073709551615"
    );
    body["boot"]["kernel"]["size"] = json!("18446744073709551616");
    rejects(&body, "E_SCHEMA");
    body["boot"]["kernel"]["size"] = json!("01");
    rejects(&body, "E_SCHEMA");
}

#[test]
fn parser_resource_boundaries_reject_before_unbounded_work() {
    let too_large = vec![b' '; MAX_INPUT_BYTES + 1];
    assert_eq!(parse_strict(&too_large).unwrap_err().code, "E_SCHEMA");
    let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert_eq!(parse_strict(deep.as_bytes()).unwrap_err().code, "E_SCHEMA");
    let boundary = format!("{}0{}", "[".repeat(64), "]".repeat(64));
    assert_eq!(
        canonicalize_json(boundary.as_bytes()).unwrap(),
        boundary.as_bytes()
    );
}
