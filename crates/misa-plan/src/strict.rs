use crate::{Error, Result};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Parse before constructing a map: escaped spellings of the same key are duplicates too.
pub fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::schema("", "record exceeds the 1 MiB input limit"));
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue { depth: 0 }
        .deserialize(&mut decoder)
        .map_err(|e| Error::schema("", format!("invalid strict JSON: {e}")))?;
    decoder
        .end()
        .map_err(|e| Error::schema("", format!("trailing JSON data: {e}")))?;
    Ok(value)
}

struct StrictValue {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if self.depth > MAX_DEPTH {
            return Err(de::Error::custom("JSON nesting exceeds 64 levels"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Misa strict JSON (unique keys and safe integral numbers)")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
            return Err(E::custom(
                "integer is outside the interoperable signed range",
            ));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        if value > MAX_SAFE_INTEGER as u64 {
            return Err(E::custom(
                "integer is outside the interoperable signed range",
            ));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Value, E> {
        Err(E::custom(
            "floating-point notation and negative zero are forbidden",
        ))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(StrictValue {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                // Do not echo attacker-controlled keys or values into diagnostics.
                return Err(de::Error::custom("duplicate object member"));
            }
            let value = map.next_value_seed(StrictValue {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
