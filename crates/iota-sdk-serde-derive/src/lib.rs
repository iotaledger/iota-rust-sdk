// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Derive macro for types that need a different serialized representation
//! depending on whether the format is human-readable (JSON) or binary (BCS).
//!
//! The IOTA SDK types are BCS-compatible: their binary encoding is part of the
//! protocol and must stay stable. Their JSON form, however, is free to be a
//! plain mirror of the Rust type. `serde`'s `#[derive]` can't express "this
//! representation only in JSON" / "that one only in BCS" because it has no
//! access to `serde::Serializer::is_human_readable`. Hand-written
//! `Serialize`/`Deserialize` impls that branch on `is_human_readable()` fill
//! that gap today, at the cost of a lot of boilerplate.
//!
//! [`SplitSerde`] generates that boilerplate. From a single type definition it
//! emits two private shadow types — one for the readable (JSON) form and one
//! for the binary (BCS) form — and the dispatching `Serialize`/`Deserialize`
//! impls. The binary shadow is always a plain `serde` derive of the base type,
//! so the wire format can't accidentally drift from the type; only the readable
//! shadow carries JSON-specific behaviour.
//!
//! # Attributes
//!
//! Type level (`#[split_serde(...)]`):
//! - `json(<serde meta>)` — forwarded verbatim as `#[serde(<serde meta>)]` on
//!   the readable shadow only. Use it for enum tagging, e.g.
//!   `#[split_serde(json(tag = "kind", rename_all = "snake_case"))]`.
//!
//! Field level (`#[split_serde(...)]`):
//! - `with = "path"` — serialize via `#[serde(with = "path")]`. Applied to both
//!   shadows, so the adapter must be `IfIsHumanReadable`-based (e.g.
//!   `crate::_serde::ReadableDisplay`, `crate::_serde::ReadableBase64Encoded`)
//!   to leave the binary form unaffected.
//! - `json(<serde meta>)` — forwarded as `#[serde(<serde meta>)]` on the
//!   readable shadow only, e.g. `#[split_serde(json(skip_serializing_if =
//!   "Option::is_none", default))]`.
//!
//! Variant level (`#[split_serde(json(<serde meta>))]`) — same as the
//! field-level `json`, applied to the readable shadow variant.
//!
//! # Limitations
//!
//! Generic types and tuple/unit structs are not supported yet; structurally
//! bespoke encodings (envelopes, transpositions, reserved variant indices)
//! should keep their hand-written impls.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitStr, parse_macro_input};

#[proc_macro_derive(SplitSerde, attributes(split_serde))]
pub fn derive_split_serde(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "`SplitSerde` does not support generic types yet",
        ));
    }

    let ty = &input.ident;
    let name = ty.to_string();
    let type_json = parse_json_directive(&input.attrs)?;
    let type_serde = type_json.map(|toks| quote!(#[serde(#toks)]));

    let (defs, ser_body, de_body) = match &input.data {
        Data::Struct(data) => expand_struct(&name, &type_serde, &data.fields)?,
        Data::Enum(data) => expand_enum(&name, &type_serde, data)?,
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                ty,
                "`SplitSerde` cannot be derived for unions",
            ));
        }
    };

    Ok(quote! {
        const _: () = {
            #defs

            #[automatically_derived]
            impl serde::Serialize for #ty {
                fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    #ser_body
                }
            }

            #[automatically_derived]
            impl<'de> serde::Deserialize<'de> for #ty {
                fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    #de_body
                }
            }
        };
    })
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

fn expand_struct(
    name: &str,
    type_serde: &Option<TokenStream2>,
    fields: &Fields,
) -> syn::Result<(TokenStream2, TokenStream2, TokenStream2)> {
    let named = match fields {
        Fields::Named(named) => &named.named,
        _ => {
            return Err(syn::Error::new_spanned(
                fields,
                "`SplitSerde` only supports structs with named fields",
            ));
        }
    };

    let mut readable_fields = Vec::new();
    let mut binary_fields = Vec::new();
    let mut idents = Vec::new();
    for field in named {
        let ident = field.ident.as_ref().unwrap();
        idents.push(ident);
        let dirs = parse_field_directives(field)?;
        let ty = &field.ty;
        let with = dirs.with_attr();
        let json = dirs.json_attr();
        readable_fields.push(quote!(#with #json #ident: #ty));
        binary_fields.push(quote!(#with #ident: #ty));
    }

    let defs = quote! {
        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(rename = #name)]
        #type_serde
        struct Readable {
            #(#readable_fields,)*
        }

        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(rename = #name)]
        struct Binary {
            #(#binary_fields,)*
        }
    };

    let ser_body = quote! {
        if serializer.is_human_readable() {
            let shadow = Readable {
                #(#idents: ::core::clone::Clone::clone(&self.#idents),)*
            };
            serde::Serialize::serialize(&shadow, serializer)
        } else {
            let shadow = Binary {
                #(#idents: ::core::clone::Clone::clone(&self.#idents),)*
            };
            serde::Serialize::serialize(&shadow, serializer)
        }
    };

    let de_body = quote! {
        if deserializer.is_human_readable() {
            let Readable { #(#idents,)* } =
                <Readable as serde::Deserialize>::deserialize(deserializer)?;
            ::core::result::Result::Ok(Self { #(#idents,)* })
        } else {
            let Binary { #(#idents,)* } =
                <Binary as serde::Deserialize>::deserialize(deserializer)?;
            ::core::result::Result::Ok(Self { #(#idents,)* })
        }
    };

    Ok((defs, ser_body, de_body))
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

fn expand_enum(
    name: &str,
    type_serde: &Option<TokenStream2>,
    data: &syn::DataEnum,
) -> syn::Result<(TokenStream2, TokenStream2, TokenStream2)> {
    let mut readable_variants = Vec::new();
    let mut binary_variants = Vec::new();
    let mut readable_ser_arms = Vec::new();
    let mut binary_ser_arms = Vec::new();
    let mut readable_de_arms = Vec::new();
    let mut binary_de_arms = Vec::new();

    for variant in &data.variants {
        let v = &variant.ident;
        let variant_json = parse_json_directive(&variant.attrs)?;
        let variant_serde = variant_json.map(|toks| quote!(#[serde(#toks)]));

        match &variant.fields {
            Fields::Named(named) => {
                let mut readable_fields = Vec::new();
                let mut binary_fields = Vec::new();
                let mut idents = Vec::new();
                for field in &named.named {
                    let ident = field.ident.as_ref().unwrap();
                    idents.push(ident);
                    let dirs = parse_field_directives(field)?;
                    let ty = &field.ty;
                    let with = dirs.with_attr();
                    let json = dirs.json_attr();
                    readable_fields.push(quote!(#with #json #ident: #ty));
                    binary_fields.push(quote!(#with #ident: #ty));
                }
                readable_variants.push(quote!(#variant_serde #v { #(#readable_fields,)* }));
                binary_variants.push(quote!(#v { #(#binary_fields,)* }));

                readable_ser_arms.push(quote! {
                    Self::#v { #(#idents,)* } => Readable::#v {
                        #(#idents: ::core::clone::Clone::clone(#idents),)*
                    }
                });
                binary_ser_arms.push(quote! {
                    Self::#v { #(#idents,)* } => Binary::#v {
                        #(#idents: ::core::clone::Clone::clone(#idents),)*
                    }
                });
                readable_de_arms
                    .push(quote!(Readable::#v { #(#idents,)* } => Self::#v { #(#idents,)* }));
                binary_de_arms
                    .push(quote!(Binary::#v { #(#idents,)* } => Self::#v { #(#idents,)* }));
            }
            Fields::Unnamed(unnamed) => {
                let mut readable_fields = Vec::new();
                let mut binary_fields = Vec::new();
                let mut bindings = Vec::new();
                for (i, field) in unnamed.unnamed.iter().enumerate() {
                    let binding =
                        syn::Ident::new(&format!("__{i}"), proc_macro2::Span::call_site());
                    bindings.push(binding);
                    let dirs = parse_field_directives(field)?;
                    let ty = &field.ty;
                    let with = dirs.with_attr();
                    let json = dirs.json_attr();
                    readable_fields.push(quote!(#with #json #ty));
                    binary_fields.push(quote!(#with #ty));
                }
                readable_variants.push(quote!(#variant_serde #v(#(#readable_fields,)*)));
                binary_variants.push(quote!(#v(#(#binary_fields,)*)));

                readable_ser_arms.push(quote! {
                    Self::#v(#(#bindings,)*) => Readable::#v(
                        #(::core::clone::Clone::clone(#bindings),)*
                    )
                });
                binary_ser_arms.push(quote! {
                    Self::#v(#(#bindings,)*) => Binary::#v(
                        #(::core::clone::Clone::clone(#bindings),)*
                    )
                });
                readable_de_arms
                    .push(quote!(Readable::#v(#(#bindings,)*) => Self::#v(#(#bindings,)*)));
                binary_de_arms.push(quote!(Binary::#v(#(#bindings,)*) => Self::#v(#(#bindings,)*)));
            }
            Fields::Unit => {
                readable_variants.push(quote!(#variant_serde #v));
                binary_variants.push(quote!(#v));
                readable_ser_arms.push(quote!(Self::#v => Readable::#v));
                binary_ser_arms.push(quote!(Self::#v => Binary::#v));
                readable_de_arms.push(quote!(Readable::#v => Self::#v));
                binary_de_arms.push(quote!(Binary::#v => Self::#v));
            }
        }
    }

    let defs = quote! {
        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(rename = #name)]
        #type_serde
        enum Readable {
            #(#readable_variants,)*
        }

        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(rename = #name)]
        enum Binary {
            #(#binary_variants,)*
        }
    };

    let ser_body = quote! {
        if serializer.is_human_readable() {
            let shadow = match self {
                #(#readable_ser_arms,)*
            };
            serde::Serialize::serialize(&shadow, serializer)
        } else {
            let shadow = match self {
                #(#binary_ser_arms,)*
            };
            serde::Serialize::serialize(&shadow, serializer)
        }
    };

    let de_body = quote! {
        if deserializer.is_human_readable() {
            let shadow = <Readable as serde::Deserialize>::deserialize(deserializer)?;
            ::core::result::Result::Ok(match shadow {
                #(#readable_de_arms,)*
            })
        } else {
            let shadow = <Binary as serde::Deserialize>::deserialize(deserializer)?;
            ::core::result::Result::Ok(match shadow {
                #(#binary_de_arms,)*
            })
        }
    };

    Ok((defs, ser_body, de_body))
}

// ---------------------------------------------------------------------------
// Attribute parsing
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FieldDirectives {
    /// Path passed to `#[serde(with = "...")]` on both shadows.
    with: Option<LitStr>,
    /// Raw tokens forwarded as `#[serde(...)]` on the readable shadow only.
    json: Option<TokenStream2>,
}

impl FieldDirectives {
    fn with_attr(&self) -> Option<TokenStream2> {
        self.with.as_ref().map(|w| quote!(#[serde(with = #w)]))
    }

    fn json_attr(&self) -> Option<TokenStream2> {
        self.json.as_ref().map(|toks| quote!(#[serde(#toks)]))
    }
}

fn parse_field_directives(field: &syn::Field) -> syn::Result<FieldDirectives> {
    let mut dirs = FieldDirectives::default();
    for attr in &field.attrs {
        if !attr.path().is_ident("split_serde") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("with") {
                dirs.with = Some(meta.value()?.parse()?);
                Ok(())
            } else if meta.path.is_ident("json") {
                let content;
                syn::parenthesized!(content in meta.input);
                dirs.json = Some(content.parse()?);
                Ok(())
            } else {
                Err(meta.error("expected `with = \"...\"` or `json(...)`"))
            }
        })?;
    }
    Ok(dirs)
}

/// Parses a single `#[split_serde(json(...))]` on a type or variant and returns
/// the inner tokens to forward to `#[serde(...)]`.
fn parse_json_directive(attrs: &[syn::Attribute]) -> syn::Result<Option<TokenStream2>> {
    let mut json = None;
    for attr in attrs {
        if !attr.path().is_ident("split_serde") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("json") {
                let content;
                syn::parenthesized!(content in meta.input);
                json = Some(content.parse()?);
                Ok(())
            } else {
                Err(meta.error("expected `json(...)`"))
            }
        })?;
    }
    Ok(json)
}
