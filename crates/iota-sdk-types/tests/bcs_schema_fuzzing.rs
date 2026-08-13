// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Grammar-driven fuzzing: generates byte sequences that conform to
//! `bcs-schema.abnf` and verifies that the BCS deserializer accepts them.
//!
//! This proves the grammar is a sound description of what BCS can decode
//! (grammar → BCS). Run with:
//!
//!   BCS_SCHEMA=1 cargo check -p iota-sdk-types --features bcs-schema,hash
//!   cargo test -p iota-sdk-types --features bcs-schema --test
//! bcs_schema_fuzzing

#![cfg(feature = "bcs-schema")]

use std::collections::HashMap;

use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};

// ─── Grammar AST ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
enum Expr {
    Empty,
    Concat(Vec<Expr>),
    Alt(Vec<Expr>),
    Literal(u8),
    /// Any byte in the inclusive range [lo, hi] — RFC 5234 `%xNN-MM` /
    /// `%dNN-MM`.
    ByteRange(u8, u8),
    RuleRef(String),
    Prim(PrimKind),
    Vector(Box<Expr>),
    Opt(Box<Expr>),
    Map(Box<Expr>, Box<Expr>),
    FixedBytes(usize),
}

#[derive(Clone, Copy, Debug)]
enum PrimKind {
    U8,
    U16,
    U32,
    U64,
    U128,
    I64,
    Bool,
    Bytes,
    Str,
}

// ─── Grammar Parser
// ───────────────────────────────────────────────────────────

fn parse_grammar(content: &str) -> HashMap<String, Expr> {
    let mut rules = HashMap::new();
    for block in content.split("\n\n") {
        let block = block.trim();
        if block.is_empty() || block.starts_with(';') {
            continue;
        }
        if let Some((name, expr)) = parse_rule_block(block) {
            rules.insert(name, expr);
        }
    }
    rules
}

fn strip_comment(s: &str) -> &str {
    if let Some(idx) = s.find(';') {
        &s[..idx]
    } else {
        s
    }
}

fn parse_rule_block(block: &str) -> Option<(String, Expr)> {
    let mut lines = block.lines();
    let first_line = lines.next()?;

    let (name, first_rhs) = first_line.split_once('=')?;
    let name = name.trim().to_string();

    // Accumulate alternatives; multi-line struct fields are concatenation
    // continuations while lines starting with `/` open a new alternative.
    let mut alternatives: Vec<String> = Vec::new();
    let mut current = strip_comment(first_rhs).trim().to_string();

    for line in lines {
        let content = strip_comment(line.trim()).trim().to_string();
        if content.is_empty() {
            continue;
        }
        if let Some(stripped) = content.strip_prefix('/') {
            alternatives.push(current);
            current = stripped.trim().to_string();
        } else if current.is_empty() {
            current = content;
        } else {
            current.push(' ');
            current.push_str(&content);
        }
    }
    alternatives.push(current);

    let exprs: Vec<Expr> = alternatives
        .iter()
        .map(|s| parse_concat(s.trim()))
        .collect();

    let expr = if exprs.len() == 1 {
        exprs.into_iter().next().unwrap()
    } else {
        Expr::Alt(exprs)
    };

    Some((name, expr))
}

fn concat_exprs(exprs: Vec<Expr>) -> Expr {
    match exprs.len() {
        0 => Expr::Empty,
        1 => exprs.into_iter().next().unwrap(),
        _ => Expr::Concat(exprs),
    }
}

fn parse_concat(s: &str) -> Expr {
    if s.is_empty() {
        return Expr::Empty;
    }
    concat_exprs(parse_token_seq(&tokenize(s)))
}

fn tokenize(s: &str) -> Vec<String> {
    // Normalize so parens and brackets become standalone tokens.
    // `*(` and `*[` are kept together so repetition-of-group is a single token.
    s.replace('(', "( ")
        .replace(')', " )")
        .replace('[', "[ ")
        .replace(']', " ]")
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// Find the indices of `/` tokens that are at group depth 0 (inline
/// alternation).
fn top_level_slash_positions(tokens: &[String]) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut depth = 0usize;
    for (i, tok) in tokens.iter().enumerate() {
        match tok.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth = depth.saturating_sub(1),
            t if t == "*(" || t == "*[" => depth += 1,
            "/" if depth == 0 => positions.push(i),
            _ => {}
        }
    }
    positions
}

/// Parse a flat token sequence, handling inline `/` alternation (RFC 5234 §3.2)
/// as well as groups, repetition, and atoms.
fn parse_token_seq(tokens: &[String]) -> Vec<Expr> {
    let slash_positions = top_level_slash_positions(tokens);
    if !slash_positions.is_empty() {
        // Build alternation arms split at each top-level `/`
        let mut arms: Vec<Expr> = Vec::new();
        let mut start = 0;
        for pos in slash_positions {
            arms.push(concat_exprs(parse_atomic_seq(&tokens[start..pos])));
            start = pos + 1;
        }
        arms.push(concat_exprs(parse_atomic_seq(&tokens[start..])));
        return vec![Expr::Alt(arms)];
    }
    parse_atomic_seq(tokens)
}

/// Parse a token sequence that contains no top-level `/` (concatenation only).
fn parse_atomic_seq(tokens: &[String]) -> Vec<Expr> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if tok == "(" {
            // Scan for matching close paren.
            // Both `(` and `*(` open a paren-depth level; both `)` and `]` close one.
            let mut depth = 1usize;
            let mut j = i + 1;
            while j < tokens.len() {
                match tokens[j].as_str() {
                    "(" | "*(" | "*[" => depth += 1,
                    "[" => depth += 1,
                    ")" | "]" => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            let inner = &tokens[i + 1..j];
            if !inner.is_empty() {
                result.push(parse_paren_expr(inner));
            }
            i = j + 1;
        } else if tok == "[" {
            // RFC 5234 §3.8 optional sequence: [ elements ] — treated as BCS Opt
            let mut depth = 1usize;
            let mut j = i + 1;
            while j < tokens.len() {
                match tokens[j].as_str() {
                    "(" | "*(" | "*[" => depth += 1,
                    "[" => depth += 1,
                    ")" | "]" => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            let inner = &tokens[i + 1..j];
            result.push(Expr::Opt(Box::new(concat_exprs(parse_token_seq(inner)))));
            i = j + 1;
        } else if tok == "*(" || tok == "*[" {
            // RFC 5234 §3.6 repetition of a group: *(elements)
            let mut depth = 1usize;
            let mut j = i + 1;
            while j < tokens.len() {
                match tokens[j].as_str() {
                    "(" | "*(" | "*[" => depth += 1,
                    "[" => depth += 1,
                    ")" | "]" => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            let inner = &tokens[i + 1..j];
            let exprs = parse_token_seq(inner);
            // Exactly 2 inner expressions → BCS map (sorted unique key-value pairs).
            let expr = if exprs.len() == 2 {
                let mut it = exprs.into_iter();
                Expr::Map(Box::new(it.next().unwrap()), Box::new(it.next().unwrap()))
            } else {
                Expr::Vector(Box::new(concat_exprs(exprs)))
            };
            result.push(expr);
            i = j + 1;
        } else if tok.starts_with('*') && tok.len() > 1 {
            // RFC 5234 §3.6 repetition of a single rule: *rulename
            result.push(Expr::Vector(Box::new(parse_atom(&tok[1..]))));
            i += 1;
        } else {
            result.push(parse_atom(tok));
            i += 1;
        }
    }
    result
}

fn parse_paren_expr(tokens: &[String]) -> Expr {
    let exprs = parse_token_seq(tokens);

    // Detect BCS vector pattern: (size *T) or (uleb128 *T) → Vector(T).
    // The length prefix and element count are kept in sync by Expr::Vector.
    if let [Expr::RuleRef(name), Expr::Vector(inner)] = exprs.as_slice()
        && (name == "size" || name == "uleb128")
    {
        return Expr::Vector(inner.clone());
    }
    // Detect BCS map pattern: (size *(K V)) or (uleb128 *(K V)) → Map(K, V).
    if let [Expr::RuleRef(name), Expr::Map(k, v)] = exprs.as_slice()
        && (name == "size" || name == "uleb128")
    {
        return Expr::Map(k.clone(), v.clone());
    }

    // RFC 5234 §3.5: anonymous group — concatenation (or alternation if `Alt` was
    // produced).
    concat_exprs(exprs)
}

fn parse_atom(token: &str) -> Expr {
    if let Some(hex) = token.strip_prefix("%x") {
        if let Some((lo_str, hi_str)) = hex.split_once('-') {
            let lo = u8::from_str_radix(lo_str, 16)
                .unwrap_or_else(|_| panic!("invalid hex range: %x{hex}"));
            let hi = u8::from_str_radix(hi_str, 16)
                .unwrap_or_else(|_| panic!("invalid hex range: %x{hex}"));
            return Expr::ByteRange(lo, hi);
        }
        let byte =
            u8::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("invalid hex literal: %x{hex}"));
        return Expr::Literal(byte);
    }
    if let Some(dec) = token.strip_prefix("%d") {
        if let Some((lo_str, hi_str)) = dec.split_once('-') {
            let lo = lo_str
                .parse::<u8>()
                .unwrap_or_else(|_| panic!("invalid decimal range: %d{dec}"));
            let hi = hi_str
                .parse::<u8>()
                .unwrap_or_else(|_| panic!("invalid decimal range: %d{dec}"));
            return Expr::ByteRange(lo, hi);
        }
        let byte = dec
            .parse::<u8>()
            .unwrap_or_else(|_| panic!("invalid decimal literal: %d{dec}"));
        return Expr::Literal(byte);
    }
    if let Some(n_str) = token.strip_suffix("OCTET")
        && let Ok(n) = n_str.parse::<usize>()
    {
        return Expr::FixedBytes(n);
    }
    match token {
        // RFC 5234 Appendix B core rule
        "OCTET" => Expr::ByteRange(0x00, 0xFF),
        // BCS primitives — handled directly rather than via grammar lookup
        "u8" => Expr::Prim(PrimKind::U8),
        "u16" => Expr::Prim(PrimKind::U16),
        "u32" => Expr::Prim(PrimKind::U32),
        "u64" => Expr::Prim(PrimKind::U64),
        "u128" => Expr::Prim(PrimKind::U128),
        "i64" => Expr::Prim(PrimKind::I64),
        "bool" => Expr::Prim(PrimKind::Bool),
        "bytes" => Expr::Prim(PrimKind::Bytes),
        "string" => Expr::Prim(PrimKind::Str),
        // unit = "" (zero bytes)
        "unit" | "\"\"" => Expr::Empty,
        other => Expr::RuleRef(other.to_string()),
    }
}

// ─── Byte Generator
// ───────────────────────────────────────────────────────────

/// Recursion depth beyond which the generator switches to minimal mode
/// (first alternative, empty vectors/options) to prevent infinite loops
/// on self-referential rules like `type-tag`.
const MAX_DEPTH: usize = 8;

/// Rule-name → generator overrides used for types whose BCS deserializer
/// applies semantic validation (e.g. scheme bytes, bitmap magic) or
/// normalizes its input (set-typed fields), beyond what the grammar
/// expresses.
type Overrides = HashMap<&'static str, fn(&mut TestHarness) -> Vec<u8>>;

fn encode_uleb128(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out
}

// ─── Test harness
// ─────────────────────────────────────────────────────────────

struct TestHarness {
    grammar: HashMap<String, Expr>,
    overrides: Overrides,
    rng: StdRng,
    failures: Vec<String>,
}

impl TestHarness {
    fn new() -> Self {
        let schema_path = concat!(env!("CARGO_MANIFEST_DIR"), "/bcs-schema.abnf");
        let content = std::fs::read_to_string(schema_path).unwrap_or_else(|_| {
            panic!(
                "failed to read {schema_path} — regenerate it with:\n  \
             BCS_SCHEMA=1 cargo check -p iota-sdk-types --features bcs-schema,hash"
            )
        });
        let grammar = parse_grammar(&content);

        // Rule-level overrides for types whose BCS deserializers apply semantic
        // validation (valid scheme byte, roaring-bitmap magic) or normalize
        // their input (set-typed deny lists) beyond the grammar.
        // The override generators are wired into gen_expr so they fire whenever the
        // named rule is referenced at any depth, fixing all cascade types too.
        let mut overrides: Overrides = Default::default();
        overrides.insert("checkpoint-contents", Self::gen_checkpoint_contents);
        overrides.insert("user-signature", Self::gen_user_signature);
        overrides.insert(
            "validator-aggregated-signature",
            Self::gen_validator_aggregated_signature,
        );
        overrides.insert(
            "checkpoint-transaction",
            Self::generate_checkpoint_transaction,
        );
        overrides.insert("move-struct", Self::gen_move_struct);
        overrides.insert("deny-rule-set", Self::gen_deny_rule_set);
        overrides.insert(
            "transaction-deny-rules-update",
            Self::gen_transaction_deny_rules_update,
        );

        Self {
            grammar,
            overrides,
            rng: StdRng::seed_from_u64(0xdead_beef_cafe_babe),
            failures: Vec::new(),
        }
    }

    fn generate(&mut self, rule: &str) -> Vec<u8> {
        if let Some(f) = self.overrides.get(rule) {
            return f(self);
        }
        let expr = self
            .grammar
            .get(rule)
            .cloned()
            .unwrap_or_else(|| panic!("unknown rule: {rule}"));
        self.gen_expr(expr, 0)
    }

    /// Generate a valid `checkpoint-transaction` in BCS wire form.
    fn generate_checkpoint_transaction(&mut self) -> Vec<u8> {
        // Intent
        let mut out = vec![
            0x01, // V1 enum discriminant
            0x00, // Intent scope = TransactionData
            0x00, // Intent version = V0
            0x00, // Intent app ID = Iota
        ];

        // Signed Transaction
        out.extend(self.generate("signed-transaction"));
        // Transaction Effects
        out.extend(self.generate("transaction-effects"));
        // Transaction Events (optional)
        let opt = self.rng.next_u32() & 1 == 0;
        if opt {
            out.push(0x01);
            out.extend(self.generate("transaction-events"));
        } else {
            out.push(0x00);
        }
        // Input objects
        let count = (self.rng.next_u32() as usize) % 6;
        out.extend(encode_uleb128(count as u64));
        for _ in 0..count {
            out.extend(self.generate("object"));
        }
        // Output objects
        let count = (self.rng.next_u32() as usize) % 6;
        out.extend(encode_uleb128(count as u64));
        for _ in 0..count {
            out.extend(self.generate("object"));
        }
        out
    }

    /// Generate a valid `checkpoint-contents` in BCS wire form.
    ///
    /// The binary format is: `%d00` (V1 discriminant) + two parallel vectors of
    /// the *same* length. The deserializer enforces this length invariant, so
    /// the two vectors must be generated in sync.
    fn gen_checkpoint_contents(&mut self) -> Vec<u8> {
        let count = (self.rng.next_u32() as usize) % 6;
        let mut out = vec![0x00]; // V1 enum discriminant
        // First vector: (digest, digest) pairs — one pair per transaction
        out.extend(encode_uleb128(count as u64));
        for _ in 0..count {
            out.extend(self.generate("digest"));
            out.extend(self.generate("digest"));
        }
        // Second vector: (vector user-signature) — same count
        out.extend(encode_uleb128(count as u64));
        for _ in 0..count {
            let n_sigs = (self.rng.next_u32() as usize) % 4;
            out.extend(encode_uleb128(n_sigs as u64));
            for _ in 0..n_sigs {
                out.extend(self.gen_user_signature());
            }
        }
        out
    }

    /// Generate a valid `user-signature` in BCS wire form.
    ///
    /// BCS `bytes` = ULEB128(97) + [0x00 scheme flag] + [64 Ed25519 sig] + [32
    /// pubkey].
    fn gen_user_signature(&mut self) -> Vec<u8> {
        const PAYLOAD_LEN: usize = 1 + 64 + 32; // scheme byte + sig + pubkey
        let mut out = encode_uleb128(PAYLOAD_LEN as u64);
        out.push(0x00); // Ed25519 scheme flag
        let mut buf = vec![0u8; 64 + 32];
        self.rng.fill_bytes(&mut buf);
        out.extend(buf);
        out
    }

    /// Generate a valid `move-struct` in BCS wire form.
    ///
    /// Layout: compressed-struct-tag + u64 version + length-prefixed bytes.
    /// `MoveStruct::new` rejects `contents` shorter than `ObjectId::LENGTH`
    /// (32 bytes), since the leading bytes are the object's id; the grammar's
    /// generic `bytes` rule cannot express that lower bound, so generate it
    /// here directly.
    fn gen_move_struct(&mut self) -> Vec<u8> {
        let mut out = self.generate("compressed-struct-tag");
        out.extend(self.rng.next_u64().to_le_bytes());
        const MIN_LEN: usize = 32; // ObjectId::LENGTH
        let len = MIN_LEN + (self.rng.next_u32() as usize) % 33; // 32..=64
        out.extend(encode_uleb128(len as u64));
        let mut buf = vec![0u8; len];
        self.rng.fill_bytes(&mut buf);
        out.extend(buf);
        out
    }

    /// Generate a canonical `deny-rule-set` in BCS wire form.
    ///
    /// The grammar expresses the wire shape (length-prefixed sequences) but
    /// not the canonical element order of the set-typed deny lists, which is
    /// a BCS-level semantic like map key order. Generate arbitrary bytes from
    /// the grammar, then normalize them through the type itself: decoding
    /// sorts and deduplicates into the sets, so re-encoding yields the
    /// canonical bytes a producer emits. This also exercises that every
    /// grammar-conformant encoding decodes.
    fn gen_deny_rule_set(&mut self) -> Vec<u8> {
        let expr = self
            .grammar
            .get("deny-rule-set")
            .cloned()
            .expect("deny-rule-set rule");
        let bytes = self.gen_expr(expr, 0);
        let value: iota_sdk_types::DenyRuleSet =
            bcs::from_bytes(&bytes).expect("grammar-conformant deny-rule-set must decode");
        bcs::to_bytes(&value).expect("serialize deny-rule-set")
    }

    /// Generate a canonical `transaction-deny-rules-update` in BCS wire form.
    ///
    /// Its six delta lists are set-typed like `deny-rule-set`'s, so the same
    /// normalization applies: generate from the grammar, decode through the
    /// type, re-encode.
    fn gen_transaction_deny_rules_update(&mut self) -> Vec<u8> {
        let expr = self
            .grammar
            .get("transaction-deny-rules-update")
            .cloned()
            .expect("transaction-deny-rules-update rule");
        let bytes = self.gen_expr(expr, 0);
        let value: iota_sdk_types::TransactionDenyRulesUpdate = bcs::from_bytes(&bytes)
            .expect("grammar-conformant transaction-deny-rules-update must decode");
        bcs::to_bytes(&value).expect("serialize transaction-deny-rules-update")
    }

    /// Generate a valid `validator-aggregated-signature` in BCS wire form.
    ///
    /// Layout: u64 epoch + 48OCTET bls-sig + BCS-bytes(roaring bitmap).
    /// Uses an empty RoaringBitmap so the bitmap deserialization always
    /// succeeds.
    fn gen_validator_aggregated_signature(&mut self) -> Vec<u8> {
        let mut out = self.rng.next_u64().to_le_bytes().to_vec(); // epoch u64
        let mut sig = vec![0u8; 48];
        self.rng.fill_bytes(&mut sig);
        out.extend(sig); // bls12381-signature = 48OCTET (no length prefix)
        // serialize empty RoaringBitmap then wrap as BCS bytes
        let bitmap = roaring::RoaringBitmap::new();
        let mut bitmap_bytes = Vec::new();
        bitmap
            .serialize_into(&mut bitmap_bytes)
            .expect("roaring serialize");
        out.extend(encode_uleb128(bitmap_bytes.len() as u64));
        out.extend(bitmap_bytes);
        out
    }

    fn gen_expr(&mut self, expr: Expr, depth: usize) -> Vec<u8> {
        let minimal = depth > MAX_DEPTH;
        match expr {
            Expr::Empty => vec![],
            Expr::Concat(parts) => {
                let mut out = Vec::new();
                for p in parts {
                    out.extend(self.gen_expr(p, depth));
                }
                out
            }
            Expr::Alt(alts) => {
                let idx = if minimal {
                    0
                } else {
                    (self.rng.next_u64() as usize) % alts.len()
                };
                self.gen_expr(alts[idx].clone(), depth)
            }
            Expr::Literal(b) => vec![b],
            Expr::ByteRange(lo, hi) => {
                let range = (hi as u16) - (lo as u16) + 1;
                vec![lo + (self.rng.next_u32() as u16 % range) as u8]
            }
            Expr::RuleRef(name) => {
                if let Some(f) = self.overrides.get(name.as_str()) {
                    return f(self);
                }
                let child = self
                    .grammar
                    .get(name.as_str())
                    .cloned()
                    .unwrap_or_else(|| panic!("unknown rule: {name}"));
                self.gen_expr(child, depth + 1)
            }
            Expr::Prim(p) => self.gen_prim(p),
            Expr::Vector(inner) => {
                // Keep vectors small: 0-5 elements normally, 0 in minimal mode
                let count: usize = if minimal {
                    0
                } else {
                    (self.rng.next_u32() as usize) % 6
                };
                let mut out = encode_uleb128(count as u64);
                for _ in 0..count {
                    out.extend(self.gen_expr((*inner).clone(), depth));
                }
                out
            }
            Expr::Opt(inner) => {
                let some = !minimal && (self.rng.next_u32() & 1 == 0);
                if some {
                    let mut out = vec![0x01];
                    out.extend(self.gen_expr((*inner).clone(), depth));
                    out
                } else {
                    vec![0x00]
                }
            }
            Expr::Map(k_expr, v_expr) => {
                let count: usize = if minimal {
                    0
                } else {
                    (self.rng.next_u32() as usize) % 4
                };
                let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..count)
                    .map(|_| {
                        (
                            self.gen_expr((*k_expr).clone(), depth),
                            self.gen_expr((*v_expr).clone(), depth),
                        )
                    })
                    .collect();
                // BCS requires maps to be in canonical (lexicographic) key order
                // and keys must be unique.
                pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
                pairs.dedup_by(|(a, _), (b, _)| a == b);
                let actual = pairs.len();
                let mut out = encode_uleb128(actual as u64);
                for (k, v) in pairs {
                    out.extend(k);
                    out.extend(v);
                }
                out
            }
            Expr::FixedBytes(n) => {
                let mut bytes = vec![0u8; n];
                self.rng.fill_bytes(&mut bytes);
                bytes
            }
        }
    }

    fn gen_prim(&mut self, p: PrimKind) -> Vec<u8> {
        match p {
            PrimKind::U8 => (self.rng.next_u32() as u8).to_le_bytes().to_vec(),
            PrimKind::U16 => (self.rng.next_u32() as u16).to_le_bytes().to_vec(),
            PrimKind::U32 => self.rng.next_u32().to_le_bytes().to_vec(),
            PrimKind::U64 => self.rng.next_u64().to_le_bytes().to_vec(),
            PrimKind::U128 => {
                let lo = self.rng.next_u64() as u128;
                let hi = self.rng.next_u64() as u128;
                ((hi << 64) | lo).to_le_bytes().to_vec()
            }
            PrimKind::I64 => (self.rng.next_u64() as i64).to_le_bytes().to_vec(),
            PrimKind::Bool => vec![self.rng.next_u32() as u8 & 1],
            PrimKind::Bytes => {
                let len = (self.rng.next_u32() as usize) % 17; // 0..=16
                let mut out = encode_uleb128(len as u64);
                let mut content = vec![0u8; len];
                self.rng.fill_bytes(&mut content);
                out.extend(content);
                out
            }
            PrimKind::Str => {
                // Non-empty ASCII identifier (a-z first char, then a-z0-9_).
                // BCS strings are UTF-8; Move Identifier validation requires non-empty
                // strings starting with a letter.  This conservative generation avoids
                // TypeParseError rejections that would mask real format bugs.
                let len = 1 + (self.rng.next_u32() as usize) % 16; // 1..=16
                let mut out = encode_uleb128(len as u64);
                // First character: always a letter
                out.push(b'a' + (self.rng.next_u32() as u8 % 26));
                // Remaining characters: letter, digit, or underscore
                for _ in 1..len {
                    let ch = match self.rng.next_u32() % 3 {
                        0 => b'a' + (self.rng.next_u32() as u8 % 26),
                        1 => b'0' + (self.rng.next_u32() as u8 % 10),
                        _ => b'_',
                    };
                    out.push(ch);
                }
                out
            }
        }
    }

    /// Generate byte sequences conforming to `rule` and assert that
    /// a round trip of deserialization followed by serialization returns the
    /// same bytes. Failures are collected into a vector rather than
    /// panicking immediately, so the full test can run to completion.
    fn check_rule<T: Serialize + DeserializeOwned>(&mut self, rule: &str) {
        const ITERATIONS: usize = 200;
        for _ in 0_usize..ITERATIONS {
            let bytes = self.generate(rule);
            match bcs::from_bytes::<T>(&bytes) {
                Ok(val) => match bcs::to_bytes(&val) {
                    Ok(round_trip) => {
                        if round_trip != bytes {
                            self.failures
                                .push(format!("Rule '{rule}': round-trip mismatch:\n  original bytes ({} bytes): {:02x?}\n  round-trip bytes ({} bytes): {:02x?}",
                                    bytes.len(),
                                    hex::encode(bytes),
                                    round_trip.len(),
                                    hex::encode(round_trip),
                                ));
                            break;
                        }
                    }
                    Err(e) => {
                        self.failures
                            .push(format!("Rule '{rule}': serialization failed: {e}"));
                        break;
                    }
                },
                Err(e) => {
                    self.failures.push(format!(
                        "Rule '{rule}': deserialization failed: {e}\n  bytes ({} bytes): {:02x?}",
                        bytes.len(),
                        hex::encode(bytes),
                    ));
                    break;
                }
            }
        }
    }
}

#[test]
fn grammar_driven_fuzzing() {
    use iota_sdk_types::*;

    let mut test = TestHarness::new();

    test.check_rule::<Address>("address");
    test.check_rule::<Argument>("argument");
    test.check_rule::<Bls12381PublicKey>("bls12381-public-key");
    test.check_rule::<Bls12381Signature>("bls12381-signature");
    test.check_rule::<CanceledTransaction>("canceled-transaction");
    test.check_rule::<ChangeEpoch>("change-epoch");
    test.check_rule::<ChangedObject>("changed-object");
    test.check_rule::<CheckpointCommitment>("checkpoint-commitment");
    test.check_rule::<CheckpointContents>("checkpoint-contents");
    test.check_rule::<CheckpointData>("checkpoint-data");
    test.check_rule::<CheckpointSummary>("checkpoint-summary");
    test.check_rule::<CheckpointTransaction>("checkpoint-transaction");
    test.check_rule::<Command>("command");
    test.check_rule::<CommandArgumentError>("command-argument-error");
    test.check_rule::<ConsensusCommitPrologueV1>("consensus-commit-prologue-v1");
    test.check_rule::<ConsensusDeterminedVersionAssignments>(
        "consensus-determined-version-assignments",
    );
    test.check_rule::<DenyRuleSet>("deny-rule-set");
    test.check_rule::<Digest>("digest");
    test.check_rule::<EndOfEpochData>("end-of-epoch-data");
    test.check_rule::<EndOfEpochTransactionKind>("end-of-epoch-transaction-kind");
    test.check_rule::<Event>("event");
    test.check_rule::<ExecutionError>("execution-error");
    test.check_rule::<ExecutionStatus>("execution-status");
    test.check_rule::<GasCostSummary>("gas-cost-summary");
    test.check_rule::<GasPayment>("gas-payment");
    test.check_rule::<GenesisObject>("genesis-object");
    test.check_rule::<GenesisTransaction>("genesis-transaction");
    test.check_rule::<IdOperation>("id-operation");
    test.check_rule::<Identifier>("identifier");
    test.check_rule::<Input>("input");
    test.check_rule::<Intent>("intent");
    test.check_rule::<MakeMoveVector>("make-move-vector");
    test.check_rule::<MergeCoins>("merge-coins");
    test.check_rule::<MoveCall>("move-call");
    test.check_rule::<MoveLocation>("move-location");
    test.check_rule::<Object>("object");
    test.check_rule::<ObjectId>("object-id");
    test.check_rule::<ObjectIn>("object-in");
    test.check_rule::<ObjectOut>("object-out");
    test.check_rule::<ObjectReference>("object-reference");
    test.check_rule::<Owner>("owner");
    test.check_rule::<PackageUpgradeError>("package-upgrade-error");
    test.check_rule::<ProgrammableTransaction>("programmable-transaction");
    test.check_rule::<Publish>("publish");
    test.check_rule::<RandomnessStateUpdate>("randomness-state-update");
    test.check_rule::<SignedCheckpointSummary>("signed-checkpoint-summary");
    test.check_rule::<SignedTransaction>("signed-transaction");
    test.check_rule::<SplitCoins>("split-coins");
    test.check_rule::<StructTag>("struct-tag");
    test.check_rule::<SystemPackage>("system-package");
    test.check_rule::<Transaction>("transaction");
    test.check_rule::<TransactionDenyRulesUpdate>("transaction-deny-rules-update");
    test.check_rule::<TransactionEffects>("transaction-effects");
    test.check_rule::<TransactionEffectsV1>("transaction-effects-v1");
    test.check_rule::<TransactionEvents>("transaction-events");
    test.check_rule::<TransactionExpiration>("transaction-expiration");
    test.check_rule::<TransactionKind>("transaction-kind");
    test.check_rule::<TransactionV1>("transaction-v1");
    test.check_rule::<TransferObjects>("transfer-objects");
    test.check_rule::<TypeArgumentError>("type-argument-error");
    test.check_rule::<TypeOrigin>("type-origin");
    test.check_rule::<TypeTag>("type-tag");
    test.check_rule::<UnchangedSharedKind>("unchanged-shared-kind");
    test.check_rule::<UnchangedSharedObject>("unchanged-shared-object");
    test.check_rule::<Upgrade>("upgrade");
    test.check_rule::<UpgradeInfo>("upgrade-info");
    test.check_rule::<UserSignature>("user-signature");
    test.check_rule::<ValidatorAggregatedSignature>("validator-aggregated-signature");
    test.check_rule::<ValidatorCommittee>("validator-committee");
    test.check_rule::<ValidatorCommitteeMember>("validator-committee-member");
    test.check_rule::<VersionAssignment>("version-assignment");

    if !test.failures.is_empty() {
        panic!(
            "{} rule(s) produced bytes that BCS rejected:\n\n{}",
            test.failures.len(),
            test.failures.join("\n\n")
        );
    }
}
