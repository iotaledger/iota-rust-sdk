// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The text a key holder signs to approve attaching their public key to a
//! `SmartAccount`.

use crate::Address;

/// The `check` line: the function that checks the proof, at the framework
/// address written as Move writes type names.
const CHECK_V1: &str = "0000000000000000000000000000000000000000000000000000000000000002::smart_account_builtin_auth::verify_key_proof";

/// Returns the text a key holder signs, as an IOTA personal message, to
/// approve attaching their key to a `SmartAccount`.
///
/// `chain_identifier` is the digest of the genesis checkpoint, as gRPC's
/// `ResponseExt::chain_id()` returns it. `account` is the account the key is
/// attached to, or the transaction sender when `new_account` is `true`.
/// `nonce` is the nonce of the transaction that attaches the key, and the
/// proof is valid up to and including `valid_until_epoch`.
///
/// Validators compute the same text to check the proof, so the result for
/// given values must never change. A new text is a new function.
pub fn key_proof_message_v1(
    chain_identifier: &[u8; 32],
    account: &Address,
    new_account: bool,
    nonce: &[u8; 32],
    valid_until_epoch: u64,
) -> String {
    format!(
        "check: {CHECK_V1}\nnetwork: {}\naccount: {}\nnew account: {new_account}\nnonce: {}\nvalid until epoch: {valid_until_epoch}",
        hex::encode(chain_identifier),
        account.to_hex(),
        hex::encode(nonce),
    )
}

#[cfg(test)]
mod tests {
    use super::key_proof_message_v1;
    use crate::Address;

    fn bytes32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    // The example of the design page, with values read from testnet. The text
    // must never change.
    #[test]
    fn message_of_the_design_example() {
        let message = key_proof_message_v1(
            &bytes32("2304aa976b1765b020886e8b5c7369e169bc779154b9c3efb4dd15c6039c0679"),
            &Address::from_hex(
                "0xf9e4f7f66304ca332d20636b5358b0b9297afbc7428bc107fc5dbc64fb204125",
            )
            .unwrap(),
            true,
            &bytes32("dbf7a1f60789ef83fe154a99c04c583785f44a74760105e17a8e7338c77c6cd1"),
            730,
        );

        assert_eq!(
            message,
            "check: 0000000000000000000000000000000000000000000000000000000000000002::smart_account_builtin_auth::verify_key_proof\n\
             network: 2304aa976b1765b020886e8b5c7369e169bc779154b9c3efb4dd15c6039c0679\n\
             account: 0xf9e4f7f66304ca332d20636b5358b0b9297afbc7428bc107fc5dbc64fb204125\n\
             new account: true\n\
             nonce: dbf7a1f60789ef83fe154a99c04c583785f44a74760105e17a8e7338c77c6cd1\n\
             valid until epoch: 730"
        );
    }

    #[test]
    fn message_for_an_existing_account_with_a_short_address() {
        let message = key_proof_message_v1(
            &[0; 32],
            &Address::from_short_hex("0x2").unwrap(),
            false,
            &[0xab; 32],
            0,
        );

        assert_eq!(
            message,
            "check: 0000000000000000000000000000000000000000000000000000000000000002::smart_account_builtin_auth::verify_key_proof\n\
             network: 0000000000000000000000000000000000000000000000000000000000000000\n\
             account: 0x0000000000000000000000000000000000000000000000000000000000000002\n\
             new account: false\n\
             nonce: abababababababababababababababababababababababababababababababab\n\
             valid until epoch: 0"
        );
    }
}
