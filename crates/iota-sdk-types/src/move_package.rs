// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::{Digest, ExecutionError, Identifier, ObjectId, Version, hash::Hasher};

/// Rust representation of upgrade policy constants in `iota::package`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum UpgradePolicy {
    /// The least restrictive policy. Permits changes to all function
    /// implementations, the removal of ability constraints on generic type
    /// parameters in function signatures, and modifications to private,
    /// public(friend), and entry function signatures. However, public function
    /// signatures and existing types cannot be changed.
    Compatible = 0,
    /// Allows adding new functionalities (e.g., new public functions or
    /// structs) but restricts changes to existing functionalities.
    Additive = 128,
    /// Limits modifications to the package’s dependencies only.
    DepOnly = 192,
}

impl UpgradePolicy {
    pub const COMPATIBLE: u8 = Self::Compatible as u8;
    pub const ADDITIVE: u8 = Self::Additive as u8;
    pub const DEP_ONLY: u8 = Self::DepOnly as u8;

    pub fn is_valid_policy(policy: &u8) -> bool {
        Self::try_from(*policy).is_ok()
    }
}

impl TryFrom<u8> for UpgradePolicy {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::Compatible as u8 => Ok(Self::Compatible),
            x if x == Self::Additive as u8 => Ok(Self::Additive),
            x if x == Self::DepOnly as u8 => Ok(Self::DepOnly),
            _ => Err(()),
        }
    }
}

/// Type corresponding to the output of `iota move build
/// --dump-bytecode-as-base64`
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MovePackageData {
    /// The package modules as a series of bytes
    #[cfg_attr(feature = "serde", serde(with = "serialization::modules"))]
    pub modules: Vec<Vec<u8>>,
    /// The package dependencies, specified by their object IDs.
    pub dependencies: Vec<ObjectId>,
    /// The package digest.
    #[cfg_attr(feature = "serde", serde(with = "serialization::digest"))]
    pub digest: Digest,
}

impl MovePackageData {
    #[cfg(feature = "hash")]
    pub fn new(modules: Vec<Vec<u8>>, dependencies: Vec<ObjectId>) -> Self {
        use crate::hash::Hasher;
        let mut components = dependencies
            .iter()
            .map(|o| o.into_bytes())
            .chain(modules.iter().map(|module| {
                let mut hasher = Hasher::new();
                hasher.update(module);
                hasher.finalize().into_inner()
            }))
            .collect::<Vec<_>>();

        // Sort so the order of the modules and the order of the dependencies
        // does not matter.
        components.sort();

        let mut hasher = Hasher::new();
        for c in components {
            hasher.update(c);
        }

        Self {
            modules,
            dependencies,
            digest: Digest::from(hasher.finalize().into_inner()),
        }
    }
}

// /// Value for the [MovePackage]'s linkage_table.
// ///
// /// # Undefined behavior
// ///
// /// Directly modifying any field is undefined behavior. The fields are only
// /// public for read-only access.
// #[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize, Hash,
// JsonSchema)] pub struct UpgradeInfo {
//     /// `Storage ID`/`Package ID` of the referred package.
//     pub upgraded_id: ObjectID,
//     /// The version of the package at `upgraded_id`.
//     pub upgraded_version: SequenceNumber,
// }

/// Upgraded package info for the linkage table
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// upgrade-info = object-id u64
/// ```
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct UpgradeInfo {
    /// Id of the upgraded packages
    pub upgraded_id: ObjectId,
    /// Version of the upgraded package
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub upgraded_version: Version,
}

// /// Store the origin of a data type where it first appeared in the version
// /// chain.
// ///
// /// A data type is identified by the name of the module and the name of the
// /// struct/enum in combination.
// ///
// /// # Undefined behavior
// ///
// /// Directly modifying any field is undefined behavior. The fields are only
// /// public for read-only access.
// #[derive(
//     Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize,
// Hash, JsonSchema, )]
// pub struct TypeOrigin {
//     /// The name of the module the data type resides in.
//     pub module_name: String,
//     /// The name of the data type.
//     ///
//     /// Here this either refers to an enum or a struct identifier.
//     // `struct_name` alias to support backwards compatibility with the old
// name     #[serde(alias = "struct_name")]
//     pub datatype_name: String,
//     /// `Storage ID` of the package, where the given type first appeared.
//     pub package: ObjectID,
// }

/// Identifies a struct and the module it was defined in
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// type-origin = identifier identifier object-id
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct TypeOrigin {
    pub module_name: Identifier,
    pub struct_name: Identifier,
    pub package: ObjectId,
}

// // serde_bytes::ByteBuf is an analog of Vec<u8> with built-in fast
// // serialization.
// #[serde_as]
// #[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize, Hash)]
// pub struct MovePackage {
//     /// The `Storage ID` of the package.
//     pub(crate) id: ObjectID,
//     /// Most move packages are uniquely identified by their ID (i.e. there is
//     /// only one version per ID), but the version is still stored because
//     /// one package may be an upgrade of another (at a different ID), in
//     /// which case its version will be one greater than the version of the
//     /// upgraded package.
//     ///
//     /// Framework packages are an exception to this rule -- all versions of
// the     /// framework packages exist at the same ID, at increasing versions.
//     ///
//     /// In all cases, packages are referred to by move calls using just their
//     /// ID, and they are always loaded at their latest version.
//     pub(crate) version: SequenceNumber,
//     /// Map module identifiers to their serialized [CompiledModule].
//     ///
//     /// All modules within a package share the `Storage ID` of their
// containing     /// package.
//     #[serde_as(as = "BTreeMap<_, Bytes>")]
//     pub(crate) module_map: BTreeMap<String, Vec<u8>>,

//     /// Maps structs and enums in a given module to a package version where
// they     /// were first defined.
//     ///
//     /// Stored as a vector for simple serialization and
//     /// deserialization.
//     pub(crate) type_origin_table: Vec<TypeOrigin>,

//     /// For each dependency, it maps the `Runtime ID` (the first package's
//     /// `Storage ID` in a version chain) of the containing package to the
//     /// `UpgradeInfo` containing the actually used version.
//     pub(crate) linkage_table: BTreeMap<ObjectID, UpgradeInfo>,
// }

/// A move package
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// object-move-package = object-id u64 move-modules type-origin-table linkage-table
///
/// move-modules = map (identifier bytes)
/// type-origin-table = vector type-origin
/// linkage-table = map (object-id upgrade-info)
/// ```
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MovePackage {
    /// Address or Id of this package
    pub id: ObjectId,
    /// Most move packages are uniquely identified by their ID (i.e. there is
    /// only one version per ID), but the version is still stored because
    /// one package may be an upgrade of another (at a different ID), in
    /// which case its version will be one greater than the version of the
    /// upgraded package.
    ///
    /// Framework packages are an exception to this rule -- all versions of the
    /// framework packages exist at the same ID, at increasing versions.
    ///
    /// In all cases, packages are referred to by move calls using just their
    /// ID, and they are always loaded at their latest version.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub version: Version,
    /// Set of modules defined by this package
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_with::As::<BTreeMap<::serde_with::Same, ::serde_with::Bytes>>")
    )]
    #[cfg_attr(
        feature = "proptest",
        strategy(
            proptest::collection::btree_map(proptest::arbitrary::any::<Identifier>(), proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..=1024), 0..=5)
        )
    )]
    pub modules: BTreeMap<Identifier, Vec<u8>>,
    /// Maps struct/module to a package version where it was first defined,
    /// stored as a vector for simple serialization and deserialization.
    pub type_origin_table: Vec<TypeOrigin>,
    /// For each dependency, maps original package ID to the info about the
    /// (upgraded) dependency version that this package is using
    #[cfg_attr(
        feature = "proptest",
        strategy(
            proptest::collection::btree_map(proptest::arbitrary::any::<ObjectId>(), proptest::arbitrary::any::<UpgradeInfo>(), 0..=5)
        )
    )]
    pub linkage_table: BTreeMap<ObjectId, UpgradeInfo>,
}

impl MovePackage {
    /// Create a package with all required data (including serialized modules,
    /// type origin and linkage tables) already supplied.
    ///
    /// It does not perform any type of validation. Ensure that the supplied
    /// parts are semantically valid.
    pub fn new(
        id: ObjectId,
        version: Version,
        modules: BTreeMap<Identifier, Vec<u8>>,
        max_move_package_size: u64,
        type_origin_table: Vec<TypeOrigin>,
        linkage_table: BTreeMap<ObjectId, UpgradeInfo>,
    ) -> Result<Self, ExecutionError> {
        let pkg = Self {
            id,
            version,
            modules,
            type_origin_table,
            linkage_table,
        };
        let object_size = pkg.size() as u64;
        if object_size > max_move_package_size {
            return Err(ExecutionError::PackageTooBig {
                object_size,
                max_object_size: max_move_package_size,
            }
            .into());
        }
        Ok(pkg)
    }

    // /// Calculate the digest of the [MovePackage].
    // pub fn digest(&self) -> [u8; 32] {
    //     Self::compute_digest_for_modules_and_deps(
    //         self.modules.values(),
    //         self.linkage_table
    //             .values()
    //             .map(|UpgradeInfo { upgraded_id, .. }| upgraded_id),
    //     )
    // }

    /// It is important that this function is shared across both the calculation
    /// of the digest for the package, and the calculation of the digest
    /// on-chain.
    pub fn compute_digest_for_modules_and_deps<'a>(
        modules: impl IntoIterator<Item = &'a Vec<u8>>,
        object_ids: impl IntoIterator<Item = &'a ObjectId>,
    ) -> Digest {
        let mut components = object_ids
            .into_iter()
            .map(|o| o.into_bytes())
            .chain(
                modules
                    .into_iter()
                    .map(|module| Hasher::digest(module).into_inner()),
            )
            .collect::<Vec<_>>();

        // NB: sorting so the order of the modules and the order of the dependencies
        // does not matter.
        components.sort();

        let mut digest = Hasher::new();
        for c in components {
            digest.update(c);
        }
        digest.finalize()
    }

    /// Retrieve the module from this package with the given [ModuleId].
    ///
    /// [ModuleId] is expected to contain the `Storage ID` of this package.
    /// In case the `Storage ID` doesn't match or the module name is not
    /// present in this package the function returns None.
    pub fn get_module(&self, package: &ObjectId, name: &Identifier) -> Option<&Vec<u8>> {
        if &self.id != package {
            None
        } else {
            self.modules.get(name)
        }
    }

    /// Return the size of the package in bytes
    pub fn size(&self) -> usize {
        let module_map_size = self
            .modules
            .iter()
            .map(|(name, module)| name.len() + module.len())
            .sum::<usize>();
        let type_origin_table_size = self
            .type_origin_table
            .iter()
            .map(
                |TypeOrigin {
                     module_name,
                     struct_name,
                     ..
                 }| module_name.len() + struct_name.len() + ObjectId::LENGTH,
            )
            .sum::<usize>();

        let linkage_table_size = self.linkage_table.len()
            * (ObjectId::LENGTH
                + (
                    ObjectId::LENGTH + 8
                    // Version
                ));

        8 /* Version */ + module_map_size + type_origin_table_size +
    linkage_table_size
    }

    /// `Package ID`/`Storage ID` of this package.
    pub fn id(&self) -> ObjectId {
        self.id
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn decrement_version(&mut self) {
        self.version.decrement().unwrap();
    }

    pub fn increment_version(&mut self) {
        self.version.increment().unwrap();
    }

    pub fn serialized_module_map(&self) -> &BTreeMap<Identifier, Vec<u8>> {
        &self.modules
    }

    pub fn type_origin_table(&self) -> &Vec<TypeOrigin> {
        &self.type_origin_table
    }

    pub fn type_origin_map(&self) -> BTreeMap<(Identifier, Identifier), ObjectId> {
        self.type_origin_table
            .iter()
            .map(
                |TypeOrigin {
                     module_name,
                     struct_name,
                     package,
                 }| { ((module_name.clone(), struct_name.clone()), *package) },
            )
            .collect()
    }

    pub fn linkage_table(&self) -> &BTreeMap<ObjectId, UpgradeInfo> {
        &self.linkage_table
    }

    // /// If `include_code` is set to `false`, the normalized module will skip
    // /// function bodies but still include the signatures.
    // pub fn normalize<S: Hash + Eq + Clone + ToString, Pool:
    // normalized::StringPool<String = S>>(     &self,
    //     pool: &mut Pool,
    //     binary_config: &BinaryConfig,
    //     include_code: bool,
    // ) -> IotaResult<BTreeMap<String, normalized::Module<S>>> {
    //     normalize_modules(pool, self.module_map.values(), binary_config,
    // include_code) }
}

#[cfg(feature = "serde")]
mod serialization {
    use base64ct::Encoding;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl MovePackageData {
        pub fn to_base64(&self) -> String {
            base64ct::Base64::encode_string(&bcs::to_bytes(self).expect("bcs encoding failed"))
        }

        pub fn from_base64(base64: &str) -> Result<Self, bcs::Error> {
            use serde::de::Error;
            bcs::from_bytes(&base64ct::Base64::decode_vec(base64).map_err(bcs::Error::custom)?)
        }
    }

    pub mod modules {
        use super::*;

        pub fn serialize<S: Serializer>(
            value: &[Vec<u8>],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            value
                .iter()
                .map(|v| base64ct::Base64::encode_string(v))
                .collect::<Vec<_>>()
                .serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bcs = Vec::<String>::deserialize(deserializer)?;
            bcs.into_iter()
                .map(|s| base64ct::Base64::decode_vec(&s).map_err(serde::de::Error::custom))
                .collect()
        }
    }

    pub mod digest {
        use super::*;

        pub fn serialize<S: Serializer>(value: &Digest, serializer: S) -> Result<S::Ok, S::Error> {
            value.as_bytes().serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Digest, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Digest::from_bytes(bytes).map_err(|e| serde::de::Error::custom(format!("{e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKAGE: &str = r#"{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}"#;

    #[test]
    fn test_serialization() {
        let package: MovePackageData = serde_json::from_str(PACKAGE).unwrap();
        let new_json = serde_json::to_string(&package).unwrap();
        assert_eq!(new_json, PACKAGE);
    }

    #[test]
    fn test_digest() {
        let json_package: MovePackageData = serde_json::from_str(PACKAGE).unwrap();
        let package = MovePackageData::new(json_package.modules, json_package.dependencies);
        assert_eq!(json_package.digest, package.digest);
    }
}
