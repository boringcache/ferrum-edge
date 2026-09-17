//! Serde helpers that require a JSON **object** where a struct is expected.
//!
//! serde's derived struct visitors implement `visit_seq` in addition to
//! `visit_map`, so a JSON array is silently accepted as a *positional*
//! construction of the struct: each element fills the next declared field and a
//! short array leaves the remaining `#[serde(default)]` fields at their
//! defaults. On admin admission surfaces that turns structurally wrong input
//! into a successfully parsed default value — `POST /restore` accepting `[]` as
//! "a backup with every collection empty" and committing the destructive
//! replacement (issue #5538), or `circuit_breaker: []` becoming a default
//! circuit-breaker object on a proxy create.
//!
//! These helpers force the map branch, so a sequence or scalar is a
//! deserialization error instead. They are cold-path admission helpers: the
//! wrappers are zero-sized and forward straight to the wrapped type's own
//! `Deserialize`, so `deny_unknown_fields`, field defaults, and custom field
//! deserializers all keep working unchanged.
//!
//! These generic serde visitors enforce shape only. Sanitize errors at the
//! document/value adapters in `deserialization`, where path and inner error are
//! separate. A generic `D::Error` may already contain a native YAML path and must
//! never be classified as a bare diagnostic here.

use std::fmt;
use std::marker::PhantomData;

use serde::Deserialize;
use serde::de::value::MapAccessDeserializer;
use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, Visitor};

/// Visitor that accepts only a map and rebuilds `T` from it.
struct ObjectVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T> Visitor<'de> for ObjectVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        T::deserialize(MapAccessDeserializer::new(map))
    }
}

/// Deserialize `T`, rejecting any input that is not an object/map.
pub fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_map(ObjectVisitor(PhantomData))
}

/// Visitor for an optional object-valued field.
struct OptionalObjectVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T> Visitor<'de> for OptionalObjectVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Option<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("null or a JSON object")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_object(deserializer).map(Some)
    }
}

/// `#[serde(default, deserialize_with = "...")]` helper for an
/// `Option<SomeStruct>` field: `null`/absent stay `None`, an object
/// deserializes normally, and a sequence or scalar is rejected instead of
/// being coerced into a default-constructed value.
pub fn deserialize_optional_object<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_option(OptionalObjectVisitor(PhantomData))
}

/// Newtype whose `Deserialize` requires the input to be a JSON object.
pub struct JsonObject<T>(pub T);

impl<'de, T> Deserialize<'de> for JsonObject<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_object(deserializer).map(JsonObject)
    }
}

/// Deserialize an array of objects, rejecting positional arrays and scalars
/// at every element. Each element retains `T`'s own field deserializers.
pub fn deserialize_object_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Vec::<JsonObject<T>>::deserialize(deserializer)
        .map(|objects| objects.into_iter().map(|object| object.0).collect())
}

/// Optional counterpart to [`deserialize_object_vec`]. Use `serde(default)`
/// on the field to preserve absence; explicit `null` remains `None` and an
/// empty array remains `Some(Vec::new())`.
pub fn deserialize_optional_object_vec<'de, D, T>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Vec<JsonObject<T>>>::deserialize(deserializer)
        .map(|objects| objects.map(|objects| objects.into_iter().map(|object| object.0).collect()))
}

/// `serde_json::from_slice` for a request body that must be a JSON object.
///
/// A top-level array, string, number, boolean, or `null` is a parse error
/// rather than a positionally/defaults-constructed `T`.
pub fn from_json_object_slice<T>(body: &[u8]) -> Result<T, serde_json::Error>
where
    T: DeserializeOwned,
{
    super::deserialization::from_json_slice::<JsonObject<T>>(body).map(|object| object.0)
}

/// Object admission from a value tree, with a separate path and sanitized cause.
pub fn from_json_object_value<T: DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, serde_json::Error> {
    super::deserialization::from_json_value::<JsonObject<T>>(value).map(|object| object.0)
}

/// Object-array admission from a value tree, with sanitized causes.
pub fn from_json_object_vec_value<T: DeserializeOwned>(
    value: serde_json::Value,
) -> Result<Vec<T>, serde_json::Error> {
    super::deserialization::from_json_value::<Vec<JsonObject<T>>>(value)
        .map(|objects| objects.into_iter().map(|object| object.0).collect())
}
