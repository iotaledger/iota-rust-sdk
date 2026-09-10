// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Before we can expose this in the public interface it likely needs to be
// wrapped so that the type from our dependency doesn't leak
pub(crate) type U256 = bnum::types::U256;

// This is a constant time assert to ensure that the backing storage for U256 is
// 32 bytes long
#[allow(unused)]
const ASSERT_32_BYTES: () = {
    assert!(core::mem::size_of::<U256>() == 32);
};

// This is a constant time assert to ensure endianness of the underlying storage
// is as expected
#[allow(unused)]
const ASSERT_ENDIANNESS: () = {
    const fn const_bytes_equal(lhs: &[u8], rhs: &[u8]) -> bool {
        if lhs.len() != rhs.len() {
            return false;
        }
        let mut i = 0;
        while i < lhs.len() {
            if lhs[i] != rhs[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    let one_le = {
        let mut buf = [0; 32];
        buf[0] = 1;
        buf
    };

    let one_be = {
        let mut buf = [0; 32];
        buf[31] = 1;
        buf
    };

    // To little endian
    assert!(const_bytes_equal(
        &one_le,
        &U256::from_le_bytes(one_le).to_le_bytes()
    ));

    // To big endian
    assert!(const_bytes_equal(
        &one_be,
        &U256::from_le_bytes(one_le).to_be_bytes()
    ));

    // From big endian
    assert!(const_bytes_equal(
        &one_le,
        &U256::from_be_bytes(one_be).to_le_bytes()
    ));
};

#[cfg(test)]
mod tests {
    #[cfg(feature = "proptest")]
    mod proptests {
        use std::str::FromStr;

        use num_bigint::BigUint;
        use proptest::prelude::*;
        use test_strategy::proptest;

        use super::super::U256;

        #[proptest]
        fn dont_crash_on_large_inputs(
            #[strategy(proptest::collection::vec(any::<u8>(), 33..1024))] bytes: Vec<u8>,
        ) {
            let big_int = BigUint::from_bytes_be(&bytes);
            let radix10 = big_int.to_str_radix(10);

            // doesn't crash
            let _ = U256::from_str_radix(&radix10, 10);
        }

        #[proptest]
        fn valid_u256_strings(
            #[strategy(proptest::collection::vec(any::<u8>(), 1..=32))] bytes: Vec<u8>,
        ) {
            let big_int = BigUint::from_bytes_be(&bytes);
            let radix10 = big_int.to_str_radix(10);

            let u256 = U256::from_str_radix(&radix10, 10).unwrap();

            assert_eq!(radix10, u256.to_str_radix(10));

            let from_str = U256::from_str(&radix10).unwrap();
            assert_eq!(from_str, u256);
            assert_eq!(radix10, from_str.to_string());
        }
    }

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn endianness() {
        let one_le = {
            let mut buf = [0; 32];
            buf[0] = 1;
            buf
        };

        let one_be = {
            let mut buf = [0; 32];
            buf[31] = 1;
            buf
        };

        let one = U256::from_le_bytes(one_le);

        // To little endian
        assert_eq!(one_le, one.to_le_bytes());

        // To big endian
        assert_eq!(one_be, one.to_be_bytes());

        // From big endian
        assert_eq!(one, U256::from_be_bytes(one_be));
    }
}
