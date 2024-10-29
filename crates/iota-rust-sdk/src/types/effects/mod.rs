mod v1;

pub use v1::{
    ChangedObject, EffectsObjectChange, IdOperation, ObjectIn, ObjectOut, TransactionEffectsV1,
    UnchangedSharedKind, UnchangedSharedObject,
};

/// The response from processing a transaction or a certified transaction
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "version")
)]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
pub enum TransactionEffects {
    #[cfg_attr(feature = "schemars", schemars(rename = "1"))]
    V1(Box<TransactionEffectsV1>),
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{TransactionEffects, TransactionEffectsV1};

    #[derive(serde_derive::Serialize)]
    #[serde(tag = "version")]
    enum ReadableEffectsRef<'a> {
        #[serde(rename = "1")]
        V1(&'a TransactionEffectsV1),
    }

    #[derive(serde_derive::Deserialize)]
    #[serde(tag = "version")]
    pub enum ReadableEffects {
        #[serde(rename = "1")]
        V1(Box<TransactionEffectsV1>),
    }

    #[derive(serde_derive::Serialize)]
    enum BinaryEffectsRef<'a> {
        V1(&'a TransactionEffectsV1),
    }

    #[derive(serde_derive::Deserialize)]
    pub enum BinaryEffects {
        V1(Box<TransactionEffectsV1>),
    }

    impl Serialize for TransactionEffects {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    TransactionEffects::V1(fx) => ReadableEffectsRef::V1(fx),
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    TransactionEffects::V1(fx) => BinaryEffectsRef::V1(fx),
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for TransactionEffects {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableEffects::deserialize(deserializer).map(|readable| match readable {
                    ReadableEffects::V1(fx) => Self::V1(fx),
                })
            } else {
                BinaryEffects::deserialize(deserializer).map(|binary| match binary {
                    BinaryEffects::V1(fx) => Self::V1(fx),
                })
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use base64ct::{Base64, Encoding};
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        use super::TransactionEffects;

        #[test]
        fn effects_fixtures() {
            // The files contain the bas64 encoded raw effects of transactions
            const GENESIS_EFFECTS: &str = include_str!("fixtures/genesis-transaction-effects");
            const SPONSOR_TX_EFFECTS: &str = include_str!("fixtures/sponsor-tx-effects");

            for fixture in [GENESIS_EFFECTS, SPONSOR_TX_EFFECTS] {
                let fixture = Base64::decode_vec(fixture.trim()).unwrap();
                let fx: TransactionEffects = bcs::from_bytes(&fixture).unwrap();
                assert_eq!(bcs::to_bytes(&fx).unwrap(), fixture);

                let json = serde_json::to_string_pretty(&fx).unwrap();
                println!("{json}");
                assert_eq!(fx, serde_json::from_str(&json).unwrap());
            }
        }
    }
}
