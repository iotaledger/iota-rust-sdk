// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Digest, ObjectId};

/// Rust representation of upgrade policy constants in `iota::package`.
#[repr(u8)]
#[derive(strum::Display, Debug, Clone, Copy, PartialEq, Eq)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
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
            .map(|o| o.into_inner())
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
