// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of `#[derive(MoveShape)]`.
//!
//! Emits an `impl crate::move_shape::MoveShape for T` whose `move_shape()`
//! returns a [`crate::move_shape::Shape`] mirroring the BCS wire layout of `T`
//! — comparable against a Move struct's `normalized::Type` so a drifted Rust
//! mirror fails loudly at test time.
//!
//! Resolution strategy mirrors Move's `normalized::Type`:
//! - Primitives map to `Shape::Bool`/`Shape::U{8..128}`.
//! - `Vec<T>` / `Option<T>` map to `Shape::Vector` / `Shape::Option`.
//! - `PhantomData<_>` becomes `Shape::Phantom` (filtered before comparison).
//! - A bare reference to one of the struct's own generic type parameters
//!   becomes `Shape::TypeParameter(idx)`.
//! - Anything else — a named type like `UID` or `Balance<T>` — becomes
//!   `Shape::Datatype { name, args }`. The macro does **not** delegate to `<Ty
//!   as MoveShape>::move_shape()`, so nested struct bodies are not inlined;
//!   verify those by giving each named type its own registry entry.
//!
//! Because nothing in the emitted body dispatches through a trait method
//! at runtime, no `T: MoveShape` bound is added to the impl — type
//! parameters are resolved purely at macro-expansion time.
//!
//! The emitted code assumes the trait + ADT live at `crate::move_shape` in the
//! consuming crate. That keeps the derive useful for `iota-sdk-move-types`'
//! `#[cfg(test)] mod move_shape` setup without requiring an attribute. Other
//! consumers would need an explicit re-export at the same path.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Data, DeriveInput, Fields, GenericArgument, GenericParam, PathArguments, Type, ext::IdentExt,
};

pub fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let ident = &input.ident;
    let name_str = ident.to_string();

    let type_params: Vec<&syn::Ident> = input
        .generics
        .params
        .iter()
        .filter_map(|p| match p {
            GenericParam::Type(t) => Some(&t.ident),
            _ => None,
        })
        .collect();

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => {
            let fields_expr = struct_fields_expr(&data.fields, &type_params)?;
            quote! {
                crate::move_shape::Shape::Struct { fields: #fields_expr }
            }
        }
        Data::Enum(data) => {
            let variants_expr = enum_variants_expr(&data.variants, &type_params)?;
            quote! {
                crate::move_shape::Shape::Enum { variants: #variants_expr }
            }
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                ident,
                "MoveShape cannot be derived for unions",
            ));
        }
    };

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics crate::move_shape::MoveShape for #ident #ty_generics #where_clause {
            const NAME: &'static str = #name_str;
            fn move_shape() -> crate::move_shape::Shape {
                #body
            }
        }
    })
}

fn enum_variants_expr(
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
    type_params: &[&syn::Ident],
) -> syn::Result<TokenStream2> {
    let mut entries = Vec::new();
    for variant in variants {
        let name = variant.ident.to_string();
        let fields_expr = match &variant.fields {
            Fields::Unit => quote! { ::std::vec![] },
            other => struct_fields_expr(other, type_params)?,
        };
        entries.push(quote! {
            crate::move_shape::Variant { name: #name, fields: #fields_expr }
        });
    }
    Ok(quote! { ::std::vec![ #( #entries ),* ] })
}

fn struct_fields_expr(fields: &Fields, type_params: &[&syn::Ident]) -> syn::Result<TokenStream2> {
    let mut entries = Vec::new();
    match fields {
        Fields::Named(named) => {
            for field in &named.named {
                // `Ident::unraw()` drops a `r#` prefix the source may carry
                // around a Rust keyword (e.g. `r#ref`, `r#for`). Move sees
                // the bare identifier, so use it for the shape too.
                let name = field.ident.as_ref().unwrap().unraw().to_string();
                let shape = type_to_shape_expr(&field.ty, type_params);
                entries.push(quote! {
                    crate::move_shape::Field { name: #name, shape: #shape }
                });
            }
        }
        // Tuple structs: Move bytecode names positional fields `pos0`,
        // `pos1`, … so we mirror that here. Lets us register Rust tuple
        // mirrors like `UQ32_32(pub u64)` against their Move counterparts.
        Fields::Unnamed(unnamed) => {
            for (idx, field) in unnamed.unnamed.iter().enumerate() {
                let name = format!("pos{idx}");
                let shape = type_to_shape_expr(&field.ty, type_params);
                entries.push(quote! {
                    crate::move_shape::Field { name: #name, shape: #shape }
                });
            }
        }
        Fields::Unit => {
            return Err(syn::Error::new_spanned(
                fields,
                "MoveShape: unit structs are not supported",
            ));
        }
    }

    Ok(quote! { ::std::vec![ #( #entries ),* ] })
}

fn type_to_shape_expr(ty: &Type, type_params: &[&syn::Ident]) -> TokenStream2 {
    if let Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
    {
        let name_ident = &seg.ident;
        let name_str = name_ident.to_string();

        // Primitives.
        match name_str.as_str() {
            "bool" => return quote! { crate::move_shape::Shape::Bool },
            "u8" => return quote! { crate::move_shape::Shape::U8 },
            "u16" => return quote! { crate::move_shape::Shape::U16 },
            "u32" => return quote! { crate::move_shape::Shape::U32 },
            "u64" => return quote! { crate::move_shape::Shape::U64 },
            "u128" => return quote! { crate::move_shape::Shape::U128 },
            "Vec" => {
                if let Some(inner) = extract_single_generic(seg) {
                    let inner_expr = type_to_shape_expr(&inner, type_params);
                    return quote! {
                        crate::move_shape::Shape::Vector(::std::boxed::Box::new(#inner_expr))
                    };
                }
            }
            "Option" => {
                if let Some(inner) = extract_single_generic(seg) {
                    let inner_expr = type_to_shape_expr(&inner, type_params);
                    return quote! {
                        crate::move_shape::Shape::Option(::std::boxed::Box::new(#inner_expr))
                    };
                }
            }
            "PhantomData" => return quote! { crate::move_shape::Shape::Phantom },
            _ => {}
        }

        // Bare reference to one of the struct's own generic type parameters —
        // single-segment path, no generic args, matching ident.
        if tp.qself.is_none()
            && tp.path.segments.len() == 1
            && matches!(seg.arguments, PathArguments::None)
            && let Some(idx) = type_params.iter().position(|p| *p == name_ident)
        {
            let idx = idx as u16;
            return quote! { crate::move_shape::Shape::TypeParameter(#idx) };
        }

        // Anything else: a named type. Resolve the Move-side name through
        // the trait const (`<Ty as MoveShape>::NAME`) so `use ... as Alias`
        // renames don't leak into the comparator — the dispatch goes to
        // the impl on the *underlying* type. Generic arguments are still
        // lowered statically through this same function.
        let args_expr = match &seg.arguments {
            PathArguments::AngleBracketed(args) => {
                let arg_exprs: Vec<TokenStream2> = args
                    .args
                    .iter()
                    .filter_map(|a| match a {
                        GenericArgument::Type(t) => Some(type_to_shape_expr(t, type_params)),
                        _ => None,
                    })
                    .collect();
                quote! { ::std::vec![ #( #arg_exprs ),* ] }
            }
            _ => quote! { ::std::vec![] },
        };
        return quote! {
            crate::move_shape::Shape::Datatype {
                name: <#ty as crate::move_shape::MoveShape>::NAME,
                args: #args_expr,
            }
        };
    }

    // Unknown / non-path type — give the comparator something to choke on
    // rather than silently passing.
    quote! { crate::move_shape::Shape::Datatype { name: "<unsupported>", args: ::std::vec![] } }
}

fn extract_single_generic(seg: &syn::PathSegment) -> Option<Type> {
    if let PathArguments::AngleBracketed(args) = &seg.arguments
        && let Some(GenericArgument::Type(ty)) = args.args.first()
    {
        return Some(ty.clone());
    }
    None
}
