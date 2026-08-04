// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Data, DeriveInput, Expr, Fields, GenericArgument, Lit, PathArguments, Type, parse_macro_input,
};

const DEFAULT_BCS_SCHEMA_FILE: &str = "bcs-schema.abnf";

#[cfg(feature = "move-shape")]
mod move_shape;

fn defined_names() -> &'static Mutex<HashMap<String, String>> {
    static NAMES: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    NAMES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[proc_macro_derive(BcsSchema, attributes(bcs_schema))]
pub fn derive_bcs_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[cfg(feature = "move-shape")]
#[proc_macro_derive(MoveShape)]
pub fn derive_move_shape(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match move_shape::expand(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

// ---------------------------------------------------------------------------
// Attribute parsing
// ---------------------------------------------------------------------------

struct TypeAttrs {
    name: Option<String>,
    definition: Option<String>,
}

struct FieldAttrs {
    skip: bool,
    as_type: Option<String>,
}

struct VariantAttrs {
    skip: bool,
    as_type: Option<String>,
}

fn parse_type_attrs(input: &DeriveInput) -> syn::Result<TypeAttrs> {
    let mut attrs = TypeAttrs {
        name: None,
        definition: None,
    };
    for attr in &input.attrs {
        if !attr.path().is_ident("bcs_schema") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                let value = meta.value()?;
                let s: syn::LitStr = value.parse()?;
                attrs.name = Some(s.value());
                Ok(())
            } else if meta.path.is_ident("definition") {
                let value = meta.value()?;
                let s: syn::LitStr = value.parse()?;
                attrs.definition = Some(s.value());
                Ok(())
            } else {
                Err(meta.error("expected `name` or `definition`"))
            }
        })?;
    }
    Ok(attrs)
}

fn parse_variant_attrs(variant: &syn::Variant) -> syn::Result<VariantAttrs> {
    let mut attrs = VariantAttrs {
        skip: false,
        as_type: None,
    };
    for attr in &variant.attrs {
        if !attr.path().is_ident("bcs_schema") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                attrs.skip = true;
                Ok(())
            } else if meta.path.is_ident("as_type") {
                let value = meta.value()?;
                let s: syn::LitStr = value.parse()?;
                attrs.as_type = Some(s.value());
                Ok(())
            } else {
                Err(meta.error("expected `skip` or `as_type`"))
            }
        })?;
    }
    Ok(attrs)
}

fn parse_field_attrs(field: &syn::Field) -> syn::Result<FieldAttrs> {
    let mut attrs = FieldAttrs {
        skip: false,
        as_type: None,
    };
    for attr in &field.attrs {
        if !attr.path().is_ident("bcs_schema") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                attrs.skip = true;
                Ok(())
            } else if meta.path.is_ident("as_type") {
                let value = meta.value()?;
                let s: syn::LitStr = value.parse()?;
                attrs.as_type = Some(s.value());
                Ok(())
            } else {
                Err(meta.error("expected `skip` or `as_type`"))
            }
        })?;
    }
    Ok(attrs)
}

// ---------------------------------------------------------------------------
// Type → ABNF mapping
// ---------------------------------------------------------------------------

fn type_to_schema(ty: &Type) -> String {
    match ty {
        Type::Path(type_path) => {
            let seg = match type_path.path.segments.last() {
                Some(s) => s,
                None => return "unknown".into(),
            };
            let name = seg.ident.to_string();
            match name.as_str() {
                "u8" | "u16" | "u32" | "u64" | "u128" | "i8" | "i16" | "i32" | "i64" | "i128"
                | "bool" => name,
                "str" | "String" => "string".into(),
                "Vec" => match extract_single_generic(seg) {
                    Some(inner) if matches_type_name(&inner, "u8") => "bytes".into(),
                    // BCS vector: `size` length prefix followed by the elements.
                    Some(inner) => {
                        format!("(size {})", wrap_for_repetition(&type_to_schema(&inner)))
                    }
                    None => "(size *unknown)".into(),
                },
                "Option" => match extract_single_generic(seg) {
                    // BCS option: opt discriminant (%d00 = None, %d01 = Some) + value.
                    Some(inner) => {
                        let inner_str = type_to_schema(&inner);
                        // Wrap complex inner types so the group is unambiguous.
                        let rhs = if (inner_str.contains(' ') && !inner_str.starts_with('('))
                            || inner_str.starts_with('*')
                            || inner_str.starts_with('[')
                        {
                            format!("({inner_str})")
                        } else {
                            inner_str
                        };
                        format!("(%d00 / %d01 {rhs})")
                    }
                    None => "(%d00 / %d01 unknown)".into(),
                },
                "Box" => match extract_single_generic(seg) {
                    Some(inner) => type_to_schema(&inner),
                    None => "unknown".into(),
                },
                "BTreeMap" | "HashMap" => match extract_two_generics(seg) {
                    // BCS map: `size` length prefix followed by key-value pairs.
                    Some((k, v)) => {
                        format!("(size *({} {}))", type_to_schema(&k), type_to_schema(&v))
                    }
                    None => "(size *(unknown unknown))".into(),
                },
                // A BCS set has the same wire shape as a vector; the grammar
                // cannot express the canonical (sorted, unique) element order,
                // which is a BCS-level semantic like map key order.
                "BTreeSet" => match extract_single_generic(seg) {
                    Some(inner) => {
                        format!("(size {})", wrap_for_repetition(&type_to_schema(&inner)))
                    }
                    None => "(size *unknown)".into(),
                },
                other => to_kebab_case(other),
            }
        }
        Type::Array(arr) => {
            let elem = type_to_schema(&arr.elem);
            if elem == "u8" {
                if let Expr::Lit(expr_lit) = &arr.len
                    && let Lit::Int(lit_int) = &expr_lit.lit
                {
                    return format!("{}OCTET", lit_int.base10_digits());
                }
                // Non-literal length — user should use #[bcs_schema(definition = "...")]
                "*OCTET".into()
            } else if let Expr::Lit(expr_lit) = &arr.len
                && let Lit::Int(lit_int) = &expr_lit.lit
            {
                // NRule or N(group) — exact repetition per RFC 5234 §3.7
                let n = lit_int.base10_digits();
                if elem.starts_with('(') || (!elem.contains(' ') && !elem.starts_with('*')) {
                    format!("{n}{elem}")
                } else {
                    format!("{n}({elem})")
                }
            } else {
                wrap_for_repetition(&elem)
            }
        }
        Type::Tuple(tuple) if tuple.elems.is_empty() => "unit".into(),
        Type::Tuple(tuple) => {
            let elems: Vec<String> = tuple.elems.iter().map(type_to_schema).collect();
            format!("({})", elems.join(" "))
        }
        _ => "unknown".into(),
    }
}

fn extract_single_generic(seg: &syn::PathSegment) -> Option<Type> {
    if let PathArguments::AngleBracketed(args) = &seg.arguments
        && let Some(GenericArgument::Type(ty)) = args.args.first()
    {
        return Some(ty.clone());
    }
    None
}

fn extract_two_generics(seg: &syn::PathSegment) -> Option<(Type, Type)> {
    if let PathArguments::AngleBracketed(args) = &seg.arguments {
        let mut iter = args.args.iter();
        if let (Some(GenericArgument::Type(k)), Some(GenericArgument::Type(v))) =
            (iter.next(), iter.next())
        {
            return Some((k.clone(), v.clone()));
        }
    }
    None
}

fn matches_type_name(ty: &Type, name: &str) -> bool {
    if let Type::Path(p) = ty
        && let Some(seg) = p.path.segments.last()
    {
        return seg.ident == name;
    }
    false
}

// ---------------------------------------------------------------------------
// RFC 5234 repetition helper
// ---------------------------------------------------------------------------

/// Prefix `s` with `*` to form a zero-or-more repetition per RFC 5234 §3.6.
///
/// If `s` is already a bracketed group (`(…)` or `[…]`) or a single bare token
/// (no whitespace, not already a repetition), the `*` can be prepended
/// directly. Otherwise `s` is wrapped in `(…)` first so the repetition applies
/// to the whole expression.
fn wrap_for_repetition(s: &str) -> String {
    if s.starts_with('(') || s.starts_with('[') || (!s.contains(' ') && !s.starts_with('*')) {
        format!("*{s}")
    } else {
        format!("*({s})")
    }
}

// ---------------------------------------------------------------------------
// CamelCase → kebab-case
// ---------------------------------------------------------------------------

fn to_kebab_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    let chars: Vec<char> = s.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        if ch == '_' {
            // Treat an underscore as an explicit word boundary. ABNF rule names
            // can't contain underscores, and Move type names like
            // `STARDUST_UPGRADE_LABEL` or `UQ32_32` reach here.
            result.push('-');
            continue;
        }
        if ch.is_uppercase() {
            if i > 0 {
                let prev = chars[i - 1];
                let prev_upper = prev.is_uppercase();
                let next_lower = i + 1 < chars.len() && chars[i + 1].is_lowercase();
                // Skip the boundary dash when the previous char was already a
                // separator (the `_` arm above pushed one), to avoid `_-`.
                if prev != '_' && (!prev_upper || next_lower) {
                    result.push('-');
                }
            }
            for lower in ch.to_lowercase() {
                result.push(lower);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Schema generation for structs
// ---------------------------------------------------------------------------

fn gen_struct(schema_name: &str, data: &syn::DataStruct) -> syn::Result<String> {
    match &data.fields {
        Fields::Named(fields) => {
            let mut parts: Vec<(String, String)> = Vec::new(); // (type_schema, field_name)
            for field in &fields.named {
                let fa = parse_field_attrs(field)?;
                if fa.skip {
                    continue;
                }
                let type_str = fa.as_type.unwrap_or_else(|| type_to_schema(&field.ty));
                let name = field.ident.as_ref().unwrap().to_string().replace('_', "-");
                parts.push((type_str, name));
            }

            if parts.is_empty() {
                return Ok(format!("{schema_name} = unit"));
            }
            if parts.len() == 1 {
                let (ty, nm) = &parts[0];
                return Ok(format!("{schema_name} = {ty}   ; {nm}"));
            }

            let max_type_len = parts.iter().map(|(t, _)| t.len()).max().unwrap_or(0);
            let indent = " ".repeat(schema_name.len() + 3); // "name = " prefix width
            let lines: Vec<String> = parts
                .iter()
                .enumerate()
                .map(|(i, (ty, name))| {
                    let pad = " ".repeat(max_type_len - ty.len());
                    if i == 0 {
                        format!("{schema_name} = {ty}{pad}   ; {name}")
                    } else {
                        format!("{indent}{ty}{pad}   ; {name}")
                    }
                })
                .collect();
            Ok(lines.join("\n"))
        }
        Fields::Unnamed(fields) => {
            if fields.unnamed.len() == 1 {
                let field = &fields.unnamed[0];
                let fa = parse_field_attrs(field)?;
                let type_str = fa.as_type.unwrap_or_else(|| type_to_schema(&field.ty));
                Ok(format!("{schema_name} = {type_str}"))
            } else {
                let mut types = Vec::new();
                for field in &fields.unnamed {
                    let fa = parse_field_attrs(field)?;
                    types.push(fa.as_type.unwrap_or_else(|| type_to_schema(&field.ty)));
                }
                Ok(format!("{schema_name} = {}", types.join(" ")))
            }
        }
        Fields::Unit => Ok(format!("{schema_name} = unit")),
    }
}

// ---------------------------------------------------------------------------
// Schema generation for enums
// ---------------------------------------------------------------------------

fn gen_enum(schema_name: &str, data: &syn::DataEnum) -> syn::Result<String> {
    let indent = " ".repeat(schema_name.len() + 1);
    let mut rows: Vec<(String, String, String)> = Vec::new(); // (prefix, fields_str, variant_name)

    for (idx, variant) in data.variants.iter().enumerate() {
        let va = parse_variant_attrs(variant)?;
        // A skipped variant is omitted from the grammar but still consumes its
        // discriminant, so the following variants keep their `%dNN` tags. This
        // is how reserved/deprecated slots (which deserialization rejects) are
        // held without appearing as valid input in the schema.
        if va.skip {
            continue;
        }
        let variant_name = variant.ident.to_string();
        let prefix = format!("%d{idx:02}");

        let fields_str = match &variant.fields {
            Fields::Unit => {
                // A variant-level as_type allows specifying payload for unit
                // variants that carry data only on the wire (e.g. repr-enum
                // mirrors used for BCS schema generation).
                match &va.as_type {
                    Some(t) => format!(" {t}"),
                    None => String::new(),
                }
            }
            Fields::Unnamed(fields) => {
                let mut types = Vec::new();
                for f in &fields.unnamed {
                    let fa = parse_field_attrs(f)?;
                    types.push(fa.as_type.unwrap_or_else(|| type_to_schema(&f.ty)));
                }
                format!(" {}", types.join(" "))
            }
            Fields::Named(fields) => {
                let mut types = Vec::new();
                for f in &fields.named {
                    let fa = parse_field_attrs(f)?;
                    if fa.skip {
                        continue;
                    }
                    types.push(fa.as_type.unwrap_or_else(|| type_to_schema(&f.ty)));
                }
                if types.is_empty() {
                    String::new()
                } else {
                    format!(" {}", types.join(" "))
                }
            }
        };

        rows.push((prefix, fields_str, variant_name));
    }

    let max_body_len = rows
        .iter()
        .map(|(p, f, _)| p.len() + f.len())
        .max()
        .unwrap_or(0);

    let lines: Vec<String> = rows
        .iter()
        .enumerate()
        .map(|(idx, (prefix, fields_str, variant_name))| {
            let pad = " ".repeat(max_body_len - prefix.len() - fields_str.len());
            if idx == 0 {
                format!("{schema_name} = {prefix}{fields_str}{pad}   ; {variant_name}")
            } else {
                format!("{indent}/ {prefix}{fields_str}{pad}   ; {variant_name}")
            }
        })
        .collect();

    Ok(lines.join("\n"))
}

// ---------------------------------------------------------------------------
// File writing
// ---------------------------------------------------------------------------

fn schema_file_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("BCS_SCHEMA_FILE") {
        return std::path::PathBuf::from(p);
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(manifest).join(DEFAULT_BCS_SCHEMA_FILE)
}

/// Built-in BCS primitive type definitions.
///
/// These are seeded into every schema file so that the grammar is always
/// self-contained.  The proc macro never derives entries for these names, so
/// they are preserved unchanged across regeneration runs.
fn primitive_entries() -> &'static [(&'static str, &'static str)] {
    &[
        ("bool", "bool    = %d00   ; false\n        / %d01   ; true"),
        ("bytes", "bytes   = size *OCTET"),
        ("i64", "i64     = 8OCTET"),
        (
            "size",
            "size    = uleb128   ; BCS sequence/string length (ULEB128-encoded)",
        ),
        ("string", "string  = size *OCTET   ; UTF-8 encoded"),
        ("u8", "u8      = 1OCTET"),
        ("u16", "u16     = 2OCTET"),
        ("u32", "u32     = 4OCTET"),
        ("u64", "u64     = 8OCTET"),
        ("u128", "u128    = 16OCTET"),
        (
            "uleb128",
            "uleb128 = *(%x80-FF) %x00-7F   ; variable-length unsigned integer",
        ),
    ]
}

fn write_schema_entry(schema_name: &str, definition: &str) {
    let path = schema_file_path();
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    // Parse existing entries — each entry is separated by a blank line.
    let mut entries: Vec<(String, String)> = Vec::new();
    for block in content.split("\n\n") {
        let trimmed = block.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip header comments (lines that are only comments with no rule)
        if !trimmed.contains('=') {
            continue;
        }
        // Extract the rule name: text before the first " ="
        let rule_name = if let Some(idx) = trimmed.find(" =") {
            trimmed[..idx].trim().to_string()
        } else if let Some(idx) = trimmed.find('=') {
            trimmed[..idx].trim().to_string()
        } else {
            continue;
        };
        entries.push((rule_name, trimmed.to_string()));
    }

    // Replace existing entry or append
    let mut found = false;
    for entry in &mut entries {
        if entry.0 == schema_name {
            entry.1 = definition.to_string();
            found = true;
            break;
        }
    }
    if !found {
        entries.push((schema_name.to_string(), definition.to_string()));
    }

    // Seed primitive definitions that the proc macro never derives itself.
    for (name, def) in primitive_entries() {
        if !entries.iter().any(|(n, _)| n == name) {
            entries.push((name.to_string(), def.to_string()));
        }
    }

    // Sort by rule name for deterministic output regardless of expansion order.
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));

    // Reconstruct the file
    let mut output =
        String::from("; Auto-generated BCS schema definitions\n; Do not edit manually\n");
    for (_, def) in &entries {
        output.push('\n');
        output.push_str(def);
        output.push('\n');
    }

    // Best-effort write — don't break compilation if it fails
    let _ = std::fs::write(&path, output);
}

// ---------------------------------------------------------------------------
// Main expansion
// ---------------------------------------------------------------------------

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let type_attrs = parse_type_attrs(input)?;
    let ident = &input.ident;
    let schema_name = type_attrs
        .name
        .unwrap_or_else(|| to_kebab_case(&ident.to_string()));

    {
        let mut names = defined_names().lock().unwrap();
        let type_name = ident.to_string();
        if let Some(existing) = names.get(&schema_name) {
            if existing != &type_name {
                return Err(syn::Error::new_spanned(
                    ident,
                    format!(
                        "BcsSchema: duplicate schema name `{schema_name}` (already used by `{existing}`)"
                    ),
                ));
            }
        } else {
            names.insert(schema_name.clone(), type_name);
        }
    }

    let definition = match type_attrs.definition {
        Some(def) => format!("{schema_name} = {def}"),
        None => match &input.data {
            Data::Struct(data) => gen_struct(&schema_name, data)?,
            Data::Enum(data) => gen_enum(&schema_name, data)?,
            Data::Union(_) => {
                return Err(syn::Error::new_spanned(
                    ident,
                    "BcsSchema cannot be derived for unions",
                ));
            }
        },
    };

    // Write the definition to the schema file only when explicitly requested via
    // the BCS_SCHEMA env var — keeps `--all-features` builds from regenerating
    // the file during normal development.
    let bcs_schema_enabled = std::env::var("BCS_SCHEMA").is_ok_and(|v| !v.is_empty() && v != "0");
    if bcs_schema_enabled {
        write_schema_entry(&schema_name, &definition);
    }

    Ok(quote! {})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kebab_case() {
        assert_eq!(to_kebab_case("Address"), "address");
        assert_eq!(to_kebab_case("ObjectId"), "object-id");
        assert_eq!(to_kebab_case("GasCostSummary"), "gas-cost-summary");
        assert_eq!(to_kebab_case("TransactionV1"), "transaction-v1");
        assert_eq!(to_kebab_case("ObjectID"), "object-id");
        assert_eq!(to_kebab_case("BTreeMap"), "b-tree-map");
        // Underscores are word boundaries, not literal characters (invalid in
        // ABNF rule names). No spurious `_-` before an uppercase letter.
        assert_eq!(
            to_kebab_case("STARDUST_UPGRADE_LABEL"),
            "stardust-upgrade-label"
        );
        assert_eq!(to_kebab_case("UQ32_32"), "uq32-32");
        assert_eq!(to_kebab_case("UQ64_64"), "uq64-64");
    }

    fn enum_schema(source: &str) -> String {
        let input: DeriveInput = syn::parse_str(source).unwrap();
        let name = to_kebab_case(&input.ident.to_string());
        let Data::Enum(data) = &input.data else {
            panic!("expected an enum");
        };
        gen_enum(&name, data).unwrap()
    }

    #[test]
    fn skip_variant_holds_its_discriminant() {
        // The skipped variant is omitted from the grammar, but the variants
        // after it keep the `%dNN` tag matching their discriminant.
        let schema = enum_schema(
            r#"
            enum Scheme {
                Ed25519(Ed25519Signature),
                #[bcs_schema(skip)]
                Bls12381Reserved,
                Passkey(PasskeyAuthenticator),
            }
            "#,
        );
        // `Passkey` keeps tag `%d02` even though it is the second emitted
        // alternative, and the skipped variant contributes no `%d01` line.
        assert_eq!(
            schema,
            "scheme = %d00 ed25519-signature       ; Ed25519\n\
             \x20      / %d02 passkey-authenticator   ; Passkey"
        );
    }
}
