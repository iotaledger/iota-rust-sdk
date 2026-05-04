# iota-sdk-bcs-schema

A procedural macro that emits an [ABNF](https://datatracker.ietf.org/doc/html/rfc5234) grammar fragment for each type it is derived on, so the BCS wire format can be described in a single machine-readable file.

## Why

A formal, human- and machine-readable description of the BCS wire format makes it possible to:

- build cross-language BCS parsers and validators without reimplementing the Rust types,
- catch accidental serialization-breaking changes at the schema level (CI diff), and
- fuzz the deserializer against grammar-valid inputs.

## What it does

`#[derive(BcsSchema)]` inspects the type's fields/variants and appends an ABNF rule to `bcs-schema.abnf` at the consuming crate's root. Supported out of the box:

- Primitives: `u8`..`u128`, `i64`, `bool`, `String`, `str`
- Generics: `Option<T>`, `Vec<T>`, `Box<T>`, `BTreeMap<K, V>`, `HashMap<K, V>`
- Fixed-size arrays `[u8; N]` and `[T; N]`
- Tuples and unit types
- Structs and enums (named, tuple, and unit variants)

Variant indices are emitted as `%dNN` literals matching the BCS variant discriminant.

Two types whose names kebab-case to the same rule (e.g. `ObjectID` and `ObjectId`) are rejected at compile time. Disambiguate with `#[bcs_schema(name = "…")]` on one of them.

## Usage

```rust
use iota_bcs_schema::BcsSchema;

#[derive(serde::Serialize, serde::Deserialize, BcsSchema)]
struct GasPayment {
    objects: Vec<ObjectReference>,
    owner: Address,
    price: u64,
    budget: u64,
}
```

produces

```abnf
gas-payment = (size *object-reference)   ; objects
              address                    ; owner
              u64                        ; price
              u64                        ; budget
```

## Attributes

| Attribute                               | Level         | Purpose                                            |
| --------------------------------------- | ------------- | -------------------------------------------------- |
| `#[bcs_schema(name = "custom-name")]`   | Type          | Override the ABNF rule name                        |
| `#[bcs_schema(definition = "32OCTET")]` | Type          | Replace the generated RHS with a manual definition |
| `#[bcs_schema(as_type = "u64")]`        | Field/variant | Reference a different wire type (e.g. for aliases) |
| `#[bcs_schema(skip)]`                   | Field         | Omit the field from the schema                     |

## Regenerating the schema

The macro only writes to disk when the `BCS_SCHEMA` env var is set, so normal development is unaffected:

```sh
# Regenerate
BCS_SCHEMA=1 cargo check -p iota-sdk-types --features bcs-schema,hash

# Normal build — no regeneration, no recompile overhead
cargo check --all-features
```

`iota-sdk-types` wires this up in its own `build.rs`: when `BCS_SCHEMA=1` is set, it removes the old file and touches all `.rs` sources so every derive re-runs. Output is sorted by rule name, so two consecutive runs produce byte-identical files.

## Limitations

- `as_type` and `definition` values are trusted verbatim — they are not validated against the actual `serde` impl.
- Custom `Serialize`/`Deserialize` impls are invisible to the macro. If the wire format diverges from the Rust layout, annotate it manually or derive on a mirror type that matches the wire format.
- `serde` attributes (`skip`, `rename`, `flatten`, `tag`, ...) are not read. Use the `bcs_schema` attributes to mirror any serde-driven differences.
