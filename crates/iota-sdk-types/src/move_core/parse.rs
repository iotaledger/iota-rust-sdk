// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use winnow::{
    ModalResult, Parser,
    ascii::multispace0,
    combinator::{alt, delimited, opt, separated},
    stream::AsChar,
    token::{one_of, take_while},
};

use crate::{Address, Identifier, StructTag, TypeParseError, TypeTag};

pub const MAX_IDENTIFIER_LENGTH: usize = 128;
pub const MAX_TYPE_TAG_NESTING: usize = 16;

/// ALLOWED_IDENTIFIERS = r"(?:[a-zA-Z][a-zA-Z0-9_]*)|(?:_[a-zA-Z0-9_]+)";
pub(crate) fn parse_identifier(input: &mut &str) -> ModalResult<Identifier, TypeParseError> {
    alt((
        "<SELF>",
        (one_of(|c: char| c.is_alpha()), valid_remainder(0)).take(),
        ('_', valid_remainder(1)).take(),
    ))
    .parse_next(input)
    .and_then(|s| {
        if s.len() > MAX_IDENTIFIER_LENGTH {
            return Err(winnow::error::ErrMode::Cut(
                TypeParseError::IdentifierMaxLengthExceeded { actual: s.len() },
            ));
        }
        Ok(s)
    })
    .map(Identifier::new_unchecked)
}

fn valid_remainder<'a>(
    minimum: usize,
) -> impl FnMut(&mut &'a str) -> ModalResult<&'a str, TypeParseError> {
    move |input: &mut &'a str| {
        take_while(
            // Use .. instead of ..= since we've already processed a single character
            minimum..MAX_IDENTIFIER_LENGTH,
            (b'_', b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9'),
        )
        .parse_next(input)
    }
}

pub(crate) fn parse_address(input: &mut &str) -> ModalResult<Address, TypeParseError> {
    ("0x", take_while(1..=64, AsChar::is_hex_digit))
        .take()
        .try_map(Address::from_prefixed_short_hex)
        .parse_next(input)
}

pub(crate) fn parse_type_tag(input: &mut &str) -> ModalResult<TypeTag, TypeParseError> {
    parse_type_tag_impl(0).parse_next(input)
}

fn parse_type_tag_impl(
    depth: usize,
) -> impl FnMut(&mut &str) -> ModalResult<TypeTag, TypeParseError> {
    move |input: &mut &str| {
        if depth > MAX_TYPE_TAG_NESTING {
            return Err(winnow::error::ErrMode::Cut(
                TypeParseError::NestingLimitExceeded,
            ));
        }
        alt((
            "u8".value(TypeTag::U8),
            "u16".value(TypeTag::U16),
            "u32".value(TypeTag::U32),
            "u64".value(TypeTag::U64),
            "u128".value(TypeTag::U128),
            "u256".value(TypeTag::U256),
            "bool".value(TypeTag::Bool),
            "address".value(TypeTag::Address),
            "signer".value(TypeTag::Signer),
            delimited(
                ("vector", multispace0, '<', multispace0),
                parse_type_tag_impl(depth + 1),
                (multispace0, '>'),
            )
            .map(|ty| TypeTag::Vector(Box::new(ty))),
            parse_struct_tag_impl(depth).map(|s| TypeTag::Struct(Box::new(s))),
        ))
        .parse_next(input)
    }
}

pub(crate) fn parse_struct_tag(input: &mut &str) -> ModalResult<StructTag, TypeParseError> {
    parse_struct_tag_impl(0).parse_next(input)
}

fn parse_struct_tag_impl(
    depth: usize,
) -> impl FnMut(&mut &str) -> ModalResult<StructTag, TypeParseError> {
    move |input: &mut &str| {
        let (address, _, module, _, name) = (
            parse_address,
            "::",
            parse_identifier,
            "::",
            parse_identifier,
        )
            .parse_next(input)?;

        // optional generic
        let generics = opt(delimited(
            (multispace0, '<', multispace0),
            parse_generics(depth),
            (multispace0, '>'),
        ))
        .parse_next(input)?
        .unwrap_or_default();

        Ok(StructTag::new(address, module, name, generics))
    }
}

fn parse_generics(
    depth: usize,
) -> impl FnMut(&mut &str) -> ModalResult<Vec<TypeTag>, TypeParseError> {
    move |input: &mut &str| {
        separated(
            1..,
            delimited(multispace0, parse_type_tag_impl(depth + 1), multispace0),
            ",",
        )
        .parse_next(input)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn test_type_tag() {
        for s in &[
            "u64",
            "bool",
            "vector<u8>",
            "vector<vector<u64>>",
            "vector<u16>",
            "vector<vector<u16>>",
            "vector<u32>",
            "vector<vector<u32>>",
            "vector<u128>",
            "vector<vector<u128>>",
            "vector<u256>",
            "vector<vector<u256>>",
            "signer",
            "0x1::M::S",
            "0x2::M::S_",
            "0x3::M_::S",
            "0x4::M_::S_",
            "0x00000000004::M::S",
            "0x1::M::S<u64>",
            "0x1::M::S<u16>",
            "0x1::M::S<u32>",
            "0x1::M::S<u256>",
            "0x1::M::S<0x2::P::Q>",
            "vector<0x1::M::S>",
            "vector<0x1::M_::S_>",
            "vector<vector<0x1::M_::S_>>",
            "0x1::M::S<vector<u8>>",
            "0x1::M::S<vector<u16>>",
            "0x1::M::S<vector<u32>>",
            "0x1::M::S<vector<u64>>",
            "0x1::M::S<vector<u128>>",
            "0x1::M::S<vector<u256>>",
            "0x1::_bar::_BAR",
            "0x1::__::__",
            "0x1::_bar::_BAR<0x2::_____::______fooo______>",
            "0x1::__::__<0x2::_____::______fooo______, 0xff::Bar____::_______foo>",
            "0x5d32d749705c5f07c741f1818df3db466128bf01677611a959b03040ac5dc774::slippage::HopSwapEvent<0x2::iota::IOTA, 0x3c86bba6a3d3ce958615ae51cc5604f58956b1583323f664cf5f048da0fcbb19::_spd::_SPD>",
        ] {
            let parsed = s.parse::<TypeTag>();
            assert!(
                parsed.is_ok(),
                "Failed to parse tag {s}: {}",
                parsed.unwrap_err()
            );
        }
    }

    #[test]
    fn test_parse_valid_struct_type() {
        let valid = vec![
            "0x1::Foo::Foo",
            "0x1::Foo_Type::Foo",
            "0x1::Foo_::Foo",
            "0x1::X_123::X32_",
            "0x1::Foo::Foo_Type",
            "0x1::Foo::Foo<0x1::ABC::ABC>",
            "0x1::Foo::Foo<0x1::ABC::ABC_Type>",
            "0x1::Foo::Foo<u8>",
            "0x1::Foo::Foo<u16>",
            "0x1::Foo::Foo<u32>",
            "0x1::Foo::Foo<u64>",
            "0x1::Foo::Foo<u128>",
            "0x1::Foo::Foo<u256>",
            "0x1::Foo::Foo<bool>",
            "0x1::Foo::Foo<address>",
            "0x1::Foo::Foo<signer>",
            "0x1::Foo::Foo<vector<0x1::ABC::ABC>>",
            "0x1::Foo::Foo<u8,bool>",
            "0x1::Foo::Foo<u8,   bool>",
            "0x1::Foo::Foo<u8  ,bool>",
            "0x1::Foo::Foo<u8 , bool  ,    vector<u8>,address,signer>",
            "0x1::Foo::Foo<vector<0x1::Foo::Struct<0x1::XYZ::XYZ>>>",
            "0x1::Foo::Foo<0x1::Foo::Struct<vector<0x1::XYZ::XYZ>, 0x1::Foo::Foo<vector<0x1::Foo::Struct<0x1::XYZ::XYZ>>>>>",
            "0x1::_bar::_BAR",
            "0x1::__::__",
            "0x1::_bar::_BAR<0x2::_____::______fooo______>",
            "0x1::__::__<0x2::_____::______fooo______, 0xff::Bar____::_______foo>",
            "0x5d32d749705c5f07c741f1818df3db466128bf01677611a959b03040ac5dc774::slippage::HopSwapEvent<0x2::iota::IOTA, 0x3c86bba6a3d3ce958615ae51cc5604f58956b1583323f664cf5f048da0fcbb19::_spd::_SPD>",
        ];
        for s in valid {
            let parsed = s.parse::<StructTag>();
            assert!(
                parsed.is_ok(),
                "Failed to parse struct {s}: {}",
                parsed.unwrap_err()
            );
        }
    }

    #[test]
    fn test_parse_struct_tag_with_type_names() {
        let names = vec![
            "address", "vector", "u128", "u256", "u64", "u32", "u16", "u8", "bool", "signer",
        ];

        let mut tests = vec![];
        for name in &names {
            for name_type in &names {
                tests.push(format!("0x1::{name}::{name_type}"))
            }
        }

        let mut instantiations = vec![];
        for ty in &tests {
            for other_ty in &tests {
                instantiations.push(format!("{ty}<{other_ty}>"))
            }
        }

        for text in tests.iter().chain(instantiations.iter()) {
            let st = text.parse::<StructTag>().expect("valid StructTag");
            assert_eq!(
                st.to_string().replace(' ', ""),
                text.replace(' ', ""),
                "text: {text:?}, StructTag: {st:?}"
            );
        }
    }

    #[test]
    fn test_type_tag_with_newlines() {
        // Newlines should be allowed in type parameters
        let valid = vec![
            "vector<\nu8\n>",
            "vector<\n    u8\n>",
            "0x1::Foo::Bar<\n    u8,\n    u64\n>",
            "0x1::Foo::Bar<\n    u8,\n    0x2::Baz::Qux<\n        bool\n    >\n>",
            "0x1::Foo::Bar  <u8>",
            "0x1::Foo::Bar\n<u8>",
            "0x1::Foo::Bar\n<\n    u8\n>",
            "vector\n<\nu8\n>",
        ];
        for s in valid {
            let parsed = s.parse::<TypeTag>();
            assert!(
                parsed.is_ok(),
                "Failed to parse type tag ({s}) with newlines: {}",
                parsed.unwrap_err()
            );
        }
    }

    #[test]
    fn test_parse_self_identifier() {
        let parsed = "<SELF>".parse::<Identifier>();
        assert!(parsed.is_ok(), "Failed to parse <SELF> as identifier");
        assert_eq!(parsed.unwrap().as_str(), "<SELF>");

        // <SELF> should work in struct tags
        let parsed = "0x1::<SELF>::Foo".parse::<StructTag>();
        assert!(
            parsed.is_ok(),
            "Failed to parse struct tag with <SELF> module: {}",
            parsed.unwrap_err()
        );

        let parsed = "0x1::Foo::<SELF>".parse::<StructTag>();
        assert!(
            parsed.is_ok(),
            "Failed to parse struct tag with <SELF> name: {}",
            parsed.unwrap_err()
        );
    }

    #[test]
    fn test_type_tag_max_nesting_depth() {
        // Generate a type tag with exactly MAX_TYPE_TAG_NESTING levels (should succeed)
        let mut valid_nested = "u8".to_string();
        for _ in 0..MAX_TYPE_TAG_NESTING {
            valid_nested = format!("vector<{valid_nested}>");
        }
        assert!(
            valid_nested.parse::<TypeTag>().is_ok(),
            "Should parse type tag with exactly {MAX_TYPE_TAG_NESTING} levels of nesting"
        );

        // Generate a type tag with MAX_TYPE_TAG_NESTING + 1 levels (should fail)
        let mut invalid_nested = "u8".to_string();
        for _ in 0..=MAX_TYPE_TAG_NESTING {
            invalid_nested = format!("vector<{invalid_nested}>");
        }
        assert!(
            invalid_nested.parse::<TypeTag>().is_err(),
            "Should reject type tag with more than {MAX_TYPE_TAG_NESTING} levels of nesting"
        );
    }

    #[test]
    fn test_struct_tag_nesting_depth() {
        // Test deeply nested struct generics
        // Each struct generic adds one nesting level
        let mut valid_struct = "0x1::A::B".to_string();
        // Start at depth 0, each generic wrapper adds 1 to the depth of inner types
        // With MAX_TYPE_TAG_NESTING iterations, the innermost type reaches depth
        // MAX_TYPE_TAG_NESTING
        for i in 0..MAX_TYPE_TAG_NESTING {
            valid_struct = format!("0x{}::A::B<{valid_struct}>", i + 2);
        }
        let parsed = valid_struct.parse::<StructTag>();
        assert!(
            parsed.is_ok(),
            "Should parse struct tag ({valid_struct}) within nesting limit: {}",
            parsed.unwrap_err()
        );

        // Add one more level to exceed the limit
        let invalid_struct = format!("0xff::A::B<{valid_struct}>");
        assert!(
            invalid_struct.parse::<StructTag>().is_err(),
            "Should reject struct tag ({invalid_struct}) exceeding nesting limit"
        );
    }

    // Custom strategies that exercise the full TypeTag grammar, including vectors
    // and nested generics. The existing `Arbitrary` derives intentionally skip
    // these (Vector has weight 0, type_params is always empty) to keep BCS
    // serialization fuzz tests fast.

    /// Strategy producing valid Move identifiers, including both
    /// letter-prefixed (`Foo`, `a1`) and underscore-prefixed (`_bar`, `__x1`).
    fn arb_identifier() -> impl Strategy<Value = Identifier> {
        prop_oneof!["[a-zA-Z][a-zA-Z0-9_]{0,127}", "_[a-zA-Z0-9_]{1,127}",]
            .prop_map(|s| Identifier::new(&s).unwrap())
    }

    /// Strategy producing a StructTag with empty type_params.
    fn arb_struct_tag_base() -> impl Strategy<Value = StructTag> {
        (any::<Address>(), arb_identifier(), arb_identifier())
            .prop_map(|(addr, module, name)| StructTag::new(addr, module, name, Vec::new()))
    }

    /// Strategy producing valid TypeTags including vectors, structs with
    /// generics, and nested combinations. Recursion is bounded to depth 4.
    fn arb_type_tag() -> impl Strategy<Value = TypeTag> {
        let leaf = prop_oneof![
            Just(TypeTag::U8),
            Just(TypeTag::U16),
            Just(TypeTag::U32),
            Just(TypeTag::U64),
            Just(TypeTag::U128),
            Just(TypeTag::U256),
            Just(TypeTag::Bool),
            Just(TypeTag::Address),
            Just(TypeTag::Signer),
        ];

        leaf.prop_recursive(
            4,  // max depth of recursion
            64, // desired_size (target number of nodes)
            3,  // expected_branch_size per recursive step
            |inner| {
                let vector_strategy = inner.clone().prop_map(|t| TypeTag::Vector(Box::new(t)));

                let struct_no_params =
                    arb_struct_tag_base().prop_map(|s| TypeTag::Struct(Box::new(s)));

                let struct_with_params = (
                    any::<Address>(),
                    arb_identifier(),
                    arb_identifier(),
                    proptest::collection::vec(inner, 1..=3),
                )
                    .prop_map(|(addr, module, name, params)| {
                        TypeTag::Struct(Box::new(StructTag::new(addr, module, name, params)))
                    });

                prop_oneof![vector_strategy, struct_no_params, struct_with_params]
            },
        )
    }

    /// Reduced set of primitive TypeTag leaves for depth-focused tests.
    fn arb_simple_leaf() -> impl Strategy<Value = TypeTag> {
        prop_oneof![Just(TypeTag::U8), Just(TypeTag::U64), Just(TypeTag::Bool)]
    }

    #[proptest]
    fn type_tag_roundtrip(#[strategy(arb_type_tag())] type_tag: TypeTag) {
        let s = type_tag.to_string();
        let parsed = s.parse::<TypeTag>().unwrap();
        assert_eq!(type_tag, parsed);
    }

    #[proptest]
    fn identifier_roundtrip(#[strategy(arb_identifier())] ident: Identifier) {
        let s = ident.to_string();
        let parsed = s.parse::<Identifier>().unwrap();
        assert_eq!(ident, parsed);
    }

    #[proptest]
    fn nested_vector_parsing(
        #[strategy(0u32..=8)] depth: u32,
        #[strategy(arb_simple_leaf())] leaf: TypeTag,
    ) {
        let mut ty = leaf;
        for _ in 0..depth {
            ty = TypeTag::Vector(Box::new(ty));
        }
        let s = ty.to_string();
        let parsed = s.parse::<TypeTag>().unwrap();
        assert_eq!(ty, parsed);
    }
}
