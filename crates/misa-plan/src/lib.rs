//! Unprivileged wire validation only. A validated record is not an approved deployment.
mod semantics;
mod strict;

use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, sync::LazyLock};
pub use strict::{MAX_INPUT_BYTES, parse as parse_strict};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub field: String,
    pub message: String,
}

impl Error {
    pub fn new(code: &'static str, field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            field: field.into(),
            message: message.into(),
        }
    }

    pub(crate) fn schema(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new("E_SCHEMA", field, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.code, self.field, self.message)
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Strata,
    Plan,
    Generation,
}

impl Domain {
    pub fn schema_version(self) -> &'static str {
        match self {
            Self::Strata => "misa.strata/v1",
            Self::Plan => "misa.plan/v1",
            Self::Generation => "misa.generation/v1",
        }
    }

    pub fn schema(self) -> &'static str {
        match self {
            Self::Strata => include_str!("../../../schemas/misa.strata-v1.schema.json"),
            Self::Plan => include_str!("../../../schemas/misa.plan-v1.schema.json"),
            Self::Generation => include_str!("../../../schemas/misa.generation-v1.schema.json"),
        }
    }

    fn detect(value: &Value) -> Result<Self> {
        match value.get("schemaVersion").and_then(Value::as_str) {
            Some("misa.strata/v1") => Ok(Self::Strata),
            Some("misa.plan/v1") => Ok(Self::Plan),
            Some("misa.generation/v1") => Ok(Self::Generation),
            _ => Err(Error::schema(
                "/schemaVersion",
                "expected an exact supported wire domain/version",
            )),
        }
    }

    fn validator(self) -> &'static jsonschema::Validator {
        static STRATA: LazyLock<jsonschema::Validator> =
            LazyLock::new(|| Domain::Strata.compile_schema());
        static PLAN: LazyLock<jsonschema::Validator> =
            LazyLock::new(|| Domain::Plan.compile_schema());
        static GENERATION: LazyLock<jsonschema::Validator> =
            LazyLock::new(|| Domain::Generation.compile_schema());
        match self {
            Self::Strata => &STRATA,
            Self::Plan => &PLAN,
            Self::Generation => &GENERATION,
        }
    }

    fn compile_schema(self) -> jsonschema::Validator {
        let schema: Value =
            serde_json::from_str(self.schema()).expect("embedded schema is valid JSON");
        jsonschema::validator_for(&schema).expect("embedded schema is valid JSON Schema")
    }
}

/// Constructible only after strict parsing, closed-schema and semantic validation.
/// Paths, signatures, contents and host state are deliberately not opened or trusted here.
#[derive(Debug)]
pub struct ValidatedRecord {
    value: Value,
    domain: Domain,
    canonical: Vec<u8>,
    digest: String,
    raw_digest: String,
}

impl ValidatedRecord {
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn domain(&self) -> Domain {
        self.domain
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn raw_digest(&self) -> &str {
        &self.raw_digest
    }
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// RFC 8785 encoding of already strictly parsed data; no Unicode normalization.
fn canonical(value: &Value) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|_| Error::schema("", "JCS serialization failed"))
}

pub fn canonicalize_json(bytes: &[u8]) -> Result<Vec<u8>> {
    canonical(&parse_strict(bytes)?)
}

pub fn validate(bytes: &[u8], expected: Option<Domain>) -> Result<ValidatedRecord> {
    let value = parse_strict(bytes)?;
    let domain = Domain::detect(&value)?;
    if expected.is_some_and(|expected| expected != domain) {
        return Err(Error::schema(
            "/schemaVersion",
            "record belongs to a different authority domain",
        ));
    }
    validate_value(&value, domain)?;
    let canonical = canonical(&value)?;
    let digest = if domain == Domain::Generation {
        let id = generation_id(&value)?;
        if value["generationId"].as_str() != Some(&id) {
            return Err(Error::new(
                "E_LOCK",
                "/generationId",
                "generation identity does not match its canonical body",
            ));
        }
        id
    } else {
        hash_bytes(&canonical)
    };
    Ok(ValidatedRecord {
        value,
        domain,
        canonical,
        digest,
        raw_digest: hash_bytes(bytes),
    })
}

fn validate_value(value: &Value, domain: Domain) -> Result<()> {
    if let Some(error) = domain.validator().iter_errors(value).next() {
        // Schema errors may include full untrusted instance values in Display.
        return Err(Error::schema(
            error.instance_path().to_string(),
            "value does not satisfy the published schema",
        ));
    }
    semantics::validate(value, domain)?;
    Ok(())
}

/// Closed-schema and semantic checks of one plan `serviceGraph` object, for init
/// adapters that compile the graph before the plan naming their output exists.
/// The full plan is still validated by [`validate`]; this is the same graph rule set.
pub fn validate_service_graph(graph: &Value) -> Result<()> {
    static GRAPH: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
        let plan: Value =
            serde_json::from_str(Domain::Plan.schema()).expect("embedded schema is valid JSON");
        let schema = serde_json::json!({
            "$defs": plan["$defs"],
            "$ref": "#/$defs/ServiceGraph",
        });
        jsonschema::validator_for(&schema).expect("embedded schema is valid JSON Schema")
    });
    if let Some(error) = GRAPH.iter_errors(graph).next() {
        return Err(Error::schema(
            format!("/serviceGraph{}", error.instance_path()),
            "value does not satisfy the published schema",
        ));
    }
    semantics::service_graph(graph)
}

struct GenerationBody<'a>(&'a serde_json::Map<String, Value>);

impl Serialize for GenerationBody<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(
            self.0.len() - usize::from(self.0.contains_key("generationId")),
        ))?;
        for (key, value) in self.0 {
            if key != "generationId" {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

fn generation_id(value: &Value) -> Result<String> {
    let body = value
        .as_object()
        .ok_or_else(|| Error::schema("", "expected an object"))?;
    let bytes = serde_jcs::to_vec(&GenerationBody(body))
        .map_err(|_| Error::schema("", "JCS serialization failed"))?;
    Ok(hash_bytes(&bytes))
}

/// Compute an identity for a schema-complete generation body, never for arbitrary JSON.
pub fn identify_generation(bytes: &[u8]) -> Result<String> {
    let mut value = parse_strict(bytes)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::schema("", "expected a generation body object"))?;
    if object.contains_key("generationId") {
        return Err(Error::schema(
            "/generationId",
            "generation body must omit its derived identity",
        ));
    }
    let id = generation_id(&value)?;
    value
        .as_object_mut()
        .expect("object checked above")
        .insert("generationId".into(), Value::String(id.clone()));
    if Domain::detect(&value)? != Domain::Generation {
        return Err(Error::schema(
            "/schemaVersion",
            "expected the generation authority domain",
        ));
    }
    validate_value(&value, Domain::Generation)?;
    Ok(id)
}
