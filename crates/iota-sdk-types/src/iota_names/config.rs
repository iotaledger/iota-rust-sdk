// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::{ObjectId, address::Address, iota_names::error::IotaNamesError};

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub struct IotaNamesConfig {
    /// Address of the `iota_names` package.
    pub package_address: Address,
    /// ID of the `IotaNames` object.
    pub object_id: ObjectId,
    /// Address of the `payments` package.
    pub payments_package_address: Address,
    /// ID of the registry table.
    pub registry_id: ObjectId,
    /// ID of the reverse registry table.
    pub reverse_registry_id: ObjectId,
}

impl Default for IotaNamesConfig {
    fn default() -> Self {
        // TODO change to mainnet https://github.com/iotaledger/iota/issues/6532
        Self::testnet()
    }
}

impl IotaNamesConfig {
    pub fn new(
        package_address: Address,
        object_id: ObjectId,
        payments_package_address: Address,
        registry_id: ObjectId,
        reverse_registry_id: ObjectId,
    ) -> Self {
        Self {
            package_address,
            object_id,
            payments_package_address,
            registry_id,
            reverse_registry_id,
        }
    }

    pub fn from_env() -> Result<Self, IotaNamesError> {
        Ok(Self::new(
            std::env::var("IOTA_NAMES_PACKAGE_ADDRESS")?.parse()?,
            std::env::var("IOTA_NAMES_OBJECT_ID")?.parse()?,
            std::env::var("IOTA_NAMES_PAYMENTS_PACKAGE_ADDRESS")?.parse()?,
            std::env::var("IOTA_NAMES_REGISTRY_ID")?.parse()?,
            std::env::var("IOTA_NAMES_REVERSE_REGISTRY_ID")?.parse()?,
        ))
    }

    // TODO add mainnet https://github.com/iotaledger/iota/issues/6532

    // Create a config based on the package and object ids published on devnet.
    pub fn devnet() -> Self {
        const PACKAGE_ADDRESS: &str =
            "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba";
        const OBJECT_ID: &str =
            "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342";
        const PAYMENTS_PACKAGE_ADDRESS: &str =
            "0x98b9b33b7c2347a8f4e8b8716fb4c7e6e1af846ec2ea063a47bba81ffe03b440";
        const REGISTRY_ID: &str =
            "0xe00b2f2400c33b4dbd3081c4dcf2e289d0544caba23a3d130b264bd756403c07";
        const REVERSE_REGISTRY_ID: &str =
            "0x1c1da17843cc453ad4079b05ce55e103b7a8cdd4db6ab42dc367b47ed6d8994d";

        let package_address = Address::from_str(PACKAGE_ADDRESS).unwrap();
        let object_id = ObjectId::from_str(OBJECT_ID).unwrap();
        let payments_package_address = Address::from_str(PAYMENTS_PACKAGE_ADDRESS).unwrap();
        let registry_id = ObjectId::from_str(REGISTRY_ID).unwrap();
        let reverse_registry_id = ObjectId::from_str(REVERSE_REGISTRY_ID).unwrap();

        Self::new(
            package_address,
            object_id,
            payments_package_address,
            registry_id,
            reverse_registry_id,
        )
    }

    // Create a config based on the package and object ids published on testnet.
    pub fn testnet() -> Self {
        const PACKAGE_ADDRESS: &str =
            "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea";
        const OBJECT_ID: &str =
            "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec";
        const PAYMENTS_PACKAGE_ADDRESS: &str =
            "0x6b1b01f4c72786a893191d5c6e73d3012f7529f86fdee3bc8c163323cee08441";
        const REGISTRY_ID: &str =
            "0x2dfc6f6d46ba55217425643a59dc85fe4d8ed273a9f74077bd0ee280dbb4f590";
        const REVERSE_REGISTRY_ID: &str =
            "0x3550bcacb793ef8b776264665e7c99fa3d897695ed664656aac693cf9cf9b76b";

        let package_address = Address::from_str(PACKAGE_ADDRESS).unwrap();
        let object_id = ObjectId::from_str(OBJECT_ID).unwrap();
        let payments_package_address = Address::from_str(PAYMENTS_PACKAGE_ADDRESS).unwrap();
        let registry_id = ObjectId::from_str(REGISTRY_ID).unwrap();
        let reverse_registry_id = ObjectId::from_str(REVERSE_REGISTRY_ID).unwrap();

        Self::new(
            package_address,
            object_id,
            payments_package_address,
            registry_id,
            reverse_registry_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_config_devnet() {
        let config = IotaNamesConfig::devnet();
        assert!(config.package_address.to_string().contains("b9d61"));
        assert!(config.object_id.to_string().contains("07c59"));
    }

    #[test]
    fn test_config_testnet() {
        let config = IotaNamesConfig::testnet();
        assert!(config.package_address.to_string().contains("7fff6"));
        assert!(config.object_id.to_string().contains("7cab4"));
    }

    #[test]
    fn test_config_default() {
        let config = IotaNamesConfig::default();
        // Default is currently Testnet
        assert_eq!(config, IotaNamesConfig::testnet());
    }

    #[test]
    fn test_config_new() {
        let addr = Address::ZERO;
        let id = ObjectId::ZERO;
        let config = IotaNamesConfig::new(addr, id, addr, id, id);
        assert_eq!(config.package_address, addr);
        assert_eq!(config.object_id, id);
    }

    #[test]
    // Sequential execution implied as we modify env vars globally
    fn test_config_from_env() {
        let vars = [
            "IOTA_NAMES_PACKAGE_ADDRESS", 
            "IOTA_NAMES_OBJECT_ID", 
            "IOTA_NAMES_PAYMENTS_PACKAGE_ADDRESS",
            "IOTA_NAMES_REGISTRY_ID",
            "IOTA_NAMES_REVERSE_REGISTRY_ID"
        ];
        
        let old_values: Vec<_> = vars.iter().map(|&k| (k, std::env::var(k))).collect();
        
        unsafe {
            std::env::set_var("IOTA_NAMES_PACKAGE_ADDRESS", "0x1");
            std::env::set_var("IOTA_NAMES_OBJECT_ID", "0x2");
            std::env::set_var("IOTA_NAMES_PAYMENTS_PACKAGE_ADDRESS", "0x3");
            std::env::set_var("IOTA_NAMES_REGISTRY_ID", "0x4");
            std::env::set_var("IOTA_NAMES_REVERSE_REGISTRY_ID", "0x5");
        }

        let config = IotaNamesConfig::from_env().unwrap();
        assert_eq!(config.package_address, Address::from_str("0x1").unwrap());
        assert_eq!(config.object_id, ObjectId::from_str("0x2").unwrap());
        
        // Restore
        for (k, v) in old_values {
            unsafe {
                if let Ok(val) = v {
                    std::env::set_var(k, val);
                } else {
                    std::env::remove_var(k);
                }
            }
        }
    }
}
