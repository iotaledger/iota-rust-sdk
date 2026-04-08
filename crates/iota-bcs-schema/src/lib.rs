use std::collections::BTreeMap;

pub use iota_bcs_schema_derive::BcsSchema;

/// Trait for types that have a BCS schema definition.
///
/// When derived, the proc macro generates an ABNF-like definition for the type
/// and appends it to a schema file (`bcs-schema.abnf` in the crate root by
/// default, overridable via the `BCS_SCHEMA_FILE` environment variable).
///
/// **All field types must also implement `BcsSchema`.** If a field's type does
/// not, compilation will fail. For type aliases (e.g. `type Version = u64`),
/// use `#[bcs_schema(as_type = "u64")]` on the field to bypass the check and
/// provide the correct schema type.
///
/// # Attributes
///
/// ## Type-level
///
/// - `#[bcs_schema(name = "custom-name")]` — override the ABNF rule name
///   (defaults to kebab-case of the Rust type name).
/// - `#[bcs_schema(definition = "32OCTET")]` — override the entire right-hand
///   side of the rule. Useful for newtypes wrapping fixed-size byte arrays
///   where the size is a const expression (`[u8; Self::LENGTH]`). When used,
///   field types are **not** checked for `BcsSchema`.
///
/// ## Field-level
///
/// - `#[bcs_schema(skip)]` — omit this field from the schema (no bound check).
/// - `#[bcs_schema(as_type = "u64")]` — override the schema type for this field
///   (no bound check on the original Rust type). Useful for type aliases like
///   `Version = u64`.
///
/// # Examples
///
/// ```ignore
/// use iota_bcs_schema::BcsSchema;
///
/// #[derive(BcsSchema)]
/// #[bcs_schema(definition = "32OCTET")]
/// pub struct Address([u8; 32]);
///
/// #[derive(BcsSchema)]
/// pub struct ObjectReference {
///     pub object_id: ObjectId,
///     #[bcs_schema(as_type = "u64")]
///     pub version: Version,
///     pub digest: Digest,
/// }
///
/// #[derive(BcsSchema)]
/// pub enum TransactionExpiration {
///     None,
///     Epoch(#[bcs_schema(as_type = "u64")] EpochId),
/// }
/// ```
pub trait BcsSchema {
    /// The ABNF rule name for this type (kebab-case).
    fn schema_name() -> &'static str;
    /// The full ABNF rule definition for this type.
    fn schema_definition() -> &'static str;
}

// ---------------------------------------------------------------------------
// Blanket impls for primitives and standard containers
// ---------------------------------------------------------------------------

macro_rules! impl_primitive {
    ($($ty:ty => $name:literal),* $(,)?) => {
        $(
            impl BcsSchema for $ty {
                fn schema_name() -> &'static str { $name }
                fn schema_definition() -> &'static str { concat!($name, " = <primitive>") }
            }
        )*
    };
}

impl_primitive! {
    u8 => "u8",
    u16 => "u16",
    u32 => "u32",
    u64 => "u64",
    u128 => "u128",
    i8 => "i8",
    i16 => "i16",
    i32 => "i32",
    i64 => "i64",
    i128 => "i128",
    bool => "bool",
    String => "string",
}

impl<T: BcsSchema> BcsSchema for Vec<T> {
    fn schema_name() -> &'static str {
        "vector"
    }
    fn schema_definition() -> &'static str {
        "vector = <container>"
    }
}

impl<T: BcsSchema> BcsSchema for Option<T> {
    fn schema_name() -> &'static str {
        "option"
    }
    fn schema_definition() -> &'static str {
        "option = <container>"
    }
}

impl<T: BcsSchema> BcsSchema for Box<T> {
    fn schema_name() -> &'static str {
        "box"
    }
    fn schema_definition() -> &'static str {
        "box = <transparent>"
    }
}

impl<K: BcsSchema, V: BcsSchema> BcsSchema for BTreeMap<K, V> {
    fn schema_name() -> &'static str {
        "map"
    }
    fn schema_definition() -> &'static str {
        "map = <container>"
    }
}

impl<const N: usize> BcsSchema for [u8; N] {
    fn schema_name() -> &'static str {
        "octet-array"
    }
    fn schema_definition() -> &'static str {
        "octet-array = <fixed-bytes>"
    }
}
