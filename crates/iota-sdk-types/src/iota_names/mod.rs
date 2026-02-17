// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod config;
pub mod constants;
pub mod error;
pub mod name;
pub mod registry;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use self::name::{Name, NameFormat};
use crate::{Address, ObjectId, StructTag, type_tag::IdentifierRef};

/// An object to manage a second-level name (SLN).
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct NameRegistration {
    id: ObjectId,
    name: Name,
    name_str: String,
    expiration_timestamp_ms: u64,
}

impl NameRegistration {
    pub fn new(id: ObjectId, name: Name, name_str: String, expiration_timestamp_ms: u64) -> Self {
        Self {
            id,
            name,
            name_str,
            expiration_timestamp_ms,
        }
    }
}

/// An object to manage a subname.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubnameRegistration {
    id: ObjectId,
    nft: NameRegistration,
}

impl SubnameRegistration {
    pub fn new(id: ObjectId, nft: NameRegistration) -> Self {
        Self { id, nft }
    }

    pub fn into_inner(self) -> NameRegistration {
        self.nft
    }
}

/// Unifying trait for [`NameRegistration`] and [`SubnameRegistration`]
pub trait IotaNamesNft {
    const MODULE: &IdentifierRef;
    const TYPE_NAME: &IdentifierRef;

    fn type_(package_id: Address) -> StructTag {
        StructTag::new(
            package_id,
            Self::MODULE.into(),
            Self::TYPE_NAME.into(),
            Vec::new(),
        )
    }

    fn name(&self) -> &Name;

    fn name_str(&self) -> &str;

    fn expiration_timestamp_ms(&self) -> u64;

    fn expiration_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.expiration_timestamp_ms())
    }

    fn has_expired(&self) -> bool {
        self.expiration_time() <= SystemTime::now()
    }

    fn id(&self) -> ObjectId;
}

impl IotaNamesNft for NameRegistration {
    const MODULE: &IdentifierRef = IdentifierRef::const_new("name_registration");
    const TYPE_NAME: &IdentifierRef = IdentifierRef::const_new("NameRegistration");

    fn name(&self) -> &Name {
        &self.name
    }

    fn name_str(&self) -> &str {
        &self.name_str
    }

    fn expiration_timestamp_ms(&self) -> u64 {
        self.expiration_timestamp_ms
    }

    fn id(&self) -> ObjectId {
        self.id
    }
}

impl IotaNamesNft for SubnameRegistration {
    const MODULE: &IdentifierRef = IdentifierRef::const_new("subname_registration");
    const TYPE_NAME: &IdentifierRef = IdentifierRef::const_new("SubnameRegistration");

    fn name(&self) -> &Name {
        self.nft.name()
    }

    fn name_str(&self) -> &str {
        self.nft.name_str()
    }

    fn expiration_timestamp_ms(&self) -> u64 {
        self.nft.expiration_timestamp_ms()
    }

    fn id(&self) -> ObjectId {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_registration() {
        let id_bytes = [1u8; 32];
        let id = ObjectId::new(id_bytes);
        let name: Name = "example.iota".parse().unwrap();
        let name_str = "example.iota".to_string();
        let timestamp = 1000;
        
        let reg = NameRegistration::new(id, name.clone(), name_str.clone(), timestamp);
        
        assert_eq!(reg.id(), id);
        assert_eq!(reg.name(), &name);
        assert_eq!(reg.name_str(), &name_str);
        assert_eq!(reg.expiration_timestamp_ms(), timestamp);
        
        // Check trait constants
        let type_tag = <NameRegistration as IotaNamesNft>::type_(Address::ZERO);
        assert!(type_tag.to_string().contains("::name_registration::NameRegistration"));
    }
    
    #[test]
    fn test_subname_registration() {
        let id = ObjectId::new([2u8; 32]);
        let nft_id = ObjectId::new([3u8; 32]);
        let name: Name = "sub.example.iota".parse().unwrap();
        let name_str = "sub.example.iota".to_string();
        let timestamp = 2000;
        
        let nft = NameRegistration::new(nft_id, name.clone(), name_str.clone(), timestamp);
        let sub = SubnameRegistration::new(id, nft.clone());
        
        assert_eq!(sub.id(), id);
        assert_eq!(sub.into_inner(), nft.clone());
        
        // Re-create for trait access
        let sub = SubnameRegistration::new(id, nft);
        assert_eq!(sub.name(), &name);
        assert_eq!(sub.name_str(), &name_str);
        assert_eq!(sub.expiration_timestamp_ms(), timestamp);
        
        let type_tag = <SubnameRegistration as IotaNamesNft>::type_(Address::ZERO);
        assert!(type_tag.to_string().contains("::subname_registration::SubnameRegistration"));
    }

    #[test]
    fn test_expiration() {
         let id = ObjectId::new([1u8; 32]);
         let name: Name = "example.iota".parse().unwrap();
         
         // Expired timestamp (1000ms after epoch)
         let expired_reg = NameRegistration::new(id, name.clone(), "example.iota".into(), 1000);
         assert!(expired_reg.has_expired());
         
         // Future timestamp
         let future_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 + 100000;
         let active_reg = NameRegistration::new(id, name, "example.iota".into(), future_ts);
         assert!(!active_reg.has_expired());
    }
}
