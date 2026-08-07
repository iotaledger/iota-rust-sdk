// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Test-only structural shape mirror.
//!
//! Each Move-mirror type implements [`MoveShape`] (via
//! `#[derive(iota_sdk_bcs_schema::MoveShape)]`) and reports its BCS wire
//! layout as a [`Shape`]. The test harness in `move_shape_compare` cross-checks
//! that shape against the canonical Move definition parsed out of
//! `packages_compiled/*`, so a renamed/reordered/retyped field in either
//! mirror fails loudly without needing an on-chain instance.
//!
//! Gated on `cfg(all(test, not(target_arch = "wasm32")))` — neither the
//! trait nor the derive impls exist in release builds (the public surface
//! of the crate is unchanged), and the shape machinery is native-only:
//! the comparator reads the fetched artifacts from disk, and its checks
//! are target-independent.

pub trait MoveShape {
    /// The Move-side struct name for this type. Defaults to the Rust
    /// ident, but using a trait const here (instead of extracting from
    /// syn at the field site) means `use ... as Alias` renames don't leak
    /// into the comparator — `Datatype { name: <AliasOf as MoveShape>::NAME, ..
    /// }` resolves through the impl on the *underlying* type.
    const NAME: &'static str;

    fn move_shape() -> Shape;
}

impl MoveShape for iota_types::ObjectId {
    const NAME: &'static str = "ObjectId";
    fn move_shape() -> Shape {
        Shape::Address
    }
}

impl MoveShape for iota_types::Address {
    const NAME: &'static str = "Address";
    fn move_shape() -> Shape {
        Shape::Address
    }
}

/// Structural mirror of [`move_binary_format::normalized::Type`], tagged so a
/// diff is human-readable and so we can express things the Move side doesn't
/// have (e.g. `Phantom` for `PhantomData<T>` fields the Rust mirror carries
/// but Move treats as a phantom type parameter, not a field).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Shape {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    Address,
    Vector(Box<Shape>),
    /// Move `option::Option<T>` is a one-field struct wrapping `vector<T>`;
    /// the comparator normalizes this match.
    Option(Box<Shape>),
    /// Produced for the type the derive was applied to. Compared against a
    /// `normalized::Struct.fields` of matching arity / names / per-field
    /// shapes.
    Struct {
        fields: Vec<Field>,
    },
    /// A reference to another named Move type — emitted for field types
    /// like `UID` or `Balance<T>`. The derive does not know the Move module
    /// path, so only `name` + `args` are carried; the comparator matches on
    /// those (this is the same coverage `normalized::Datatype` gives us
    /// without resolving module addresses).
    Datatype {
        name: &'static str,
        args: Vec<Shape>,
    },
    /// A bare type-parameter reference at position `n`.
    TypeParameter(u16),
    /// A `PhantomData<_>` field on the Rust mirror — filtered out before
    /// comparison since Move models phantom types at the struct level, not
    /// per-field.
    Phantom,
    /// Produced for the type the derive was applied to when it's an enum.
    /// Compared against a `normalized::Enum.variants` of matching arity /
    /// names / per-variant field shapes.
    Enum {
        variants: Vec<Variant>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    pub name: &'static str,
    pub shape: Shape,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Variant {
    pub name: &'static str,
    pub fields: Vec<Field>,
}
