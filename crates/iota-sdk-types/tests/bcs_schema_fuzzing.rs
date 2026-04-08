// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Grammar-driven fuzzing: generates byte sequences that conform to
//! `bcs-schema.abnf` and verifies that the BCS deserializer accepts them.
//!
//! This proves the grammar is a sound description of what BCS can decode
//! (grammar → BCS). Run with:
//!
//!   BCS_SCHEMA=1 cargo check -p iota-sdk-types --features bcs-schema
//!   cargo test -p iota-sdk-types --features bcs-schema --test
//! bcs_schema_fuzzing

#![cfg(feature = "bcs-schema")]

use std::collections::HashMap;

use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};

// ─── Grammar AST ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Expr {
    Empty,
    Concat(Vec<Expr>),
    Alt(Vec<Expr>),
    Literal(u8),
    RuleRef(String),
    Prim(PrimKind),
    Vector(Box<Expr>),
    Opt(Box<Expr>),
    Map(Box<Expr>, Box<Expr>),
    FixedBytes(usize),
}

#[derive(Debug, Clone)]
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
        if content.starts_with('/') {
            alternatives.push(current);
            current = content[1..].trim().to_string();
        } else {
            if current.is_empty() {
                current = content;
            } else {
                current.push(' ');
                current.push_str(&content);
            }
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

fn parse_concat(s: &str) -> Expr {
    if s.is_empty() {
        return Expr::Empty;
    }
    let tokens = tokenize(s);
    let exprs = parse_token_seq(&tokens);
    match exprs.len() {
        0 => Expr::Empty,
        1 => exprs.into_iter().next().unwrap(),
        _ => Expr::Concat(exprs),
    }
}

fn tokenize(s: &str) -> Vec<String> {
    // Normalize so parens become standalone tokens
    s.replace('(', "( ")
        .replace(')', " )")
        .split_whitespace()
        .map(String::from)
        .collect()
}

fn parse_token_seq(tokens: &[String]) -> Vec<Expr> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == "(" {
            // Scan for matching close paren
            let mut depth = 1usize;
            let mut j = i + 1;
            while j < tokens.len() {
                match tokens[j].as_str() {
                    "(" => depth += 1,
                    ")" => {
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
        } else {
            result.push(parse_atom(&tokens[i]));
            i += 1;
        }
    }
    result
}

fn parse_paren_expr(tokens: &[String]) -> Expr {
    fn tail(tokens: &[String]) -> Expr {
        // Everything after the keyword — may itself contain nested parens
        let exprs = parse_token_seq(&tokens[1..]);
        match exprs.len() {
            0 => Expr::Empty,
            1 => exprs.into_iter().next().unwrap(),
            _ => Expr::Concat(exprs),
        }
    }
    fn group(tokens: &[String]) -> Expr {
        let exprs = parse_token_seq(tokens);
        match exprs.len() {
            0 => Expr::Empty,
            1 => exprs.into_iter().next().unwrap(),
            _ => Expr::Concat(exprs),
        }
    }

    match tokens.first().map(|s| s.as_str()) {
        Some("vector") => Expr::Vector(Box::new(tail(tokens))),
        Some("option") => Expr::Opt(Box::new(tail(tokens))),
        Some("map") => {
            // map takes exactly two type arguments — keep atom-based parsing for k/v
            Expr::Map(
                Box::new(tokens.get(1).map_or(Expr::Empty, |s| parse_atom(s))),
                Box::new(tokens.get(2).map_or(Expr::Empty, |s| parse_atom(s))),
            )
        }
        // Bare parenthesised group used as anonymous concat: (a b c)
        _ => group(tokens),
    }
}

fn parse_atom(token: &str) -> Expr {
    if let Some(hex) = token.strip_prefix("%x") {
        let byte =
            u8::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("invalid hex literal: %x{hex}"));
        return Expr::Literal(byte);
    }
    if let Some(n_str) = token.strip_suffix("OCTET") {
        if let Ok(n) = n_str.parse::<usize>() {
            return Expr::FixedBytes(n);
        }
    }
    match token {
        "u8" => Expr::Prim(PrimKind::U8),
        "u16" => Expr::Prim(PrimKind::U16),
        "u32" => Expr::Prim(PrimKind::U32),
        "u64" => Expr::Prim(PrimKind::U64),
        "u128" => Expr::Prim(PrimKind::U128),
        "i64" => Expr::Prim(PrimKind::I64),
        "bool" => Expr::Prim(PrimKind::Bool),
        "bytes" => Expr::Prim(PrimKind::Bytes),
        "string" => Expr::Prim(PrimKind::Str),
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
/// applies semantic validation (e.g. scheme bytes, bitmap magic).
type Overrides = HashMap<&'static str, fn(&mut StdRng) -> Vec<u8>>;

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

/// Generate a valid `checkpoint-contents` in BCS wire form.
///
/// The binary format is: `%x00` (V1 discriminant) + two parallel vectors of
/// the *same* length. The deserializer enforces this length invariant, so the
/// two vectors must be generated in sync.
fn gen_checkpoint_contents(rng: &mut StdRng) -> Vec<u8> {
    let count = (rng.next_u32() as usize) % 6;
    let mut out = vec![0x00]; // V1 enum discriminant
    // First vector: (digest, digest) pairs — one pair per transaction
    out.extend(encode_uleb128(count as u64));
    for _ in 0..count {
        // Each digest = %x20 32OCTET
        out.push(0x20);
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        out.extend_from_slice(&buf);
        out.push(0x20);
        rng.fill_bytes(&mut buf);
        out.extend_from_slice(&buf);
    }
    // Second vector: (vector user-signature) — same count
    out.extend(encode_uleb128(count as u64));
    for _ in 0..count {
        let n_sigs = (rng.next_u32() as usize) % 4;
        out.extend(encode_uleb128(n_sigs as u64));
        for _ in 0..n_sigs {
            out.extend(gen_user_signature(rng));
        }
    }
    out
}

/// Generate a valid `user-signature` in BCS wire form.
///
/// BCS `bytes` = ULEB128(97) + [0x00 scheme flag] + [64 Ed25519 sig] + [32
/// pubkey].
fn gen_user_signature(rng: &mut StdRng) -> Vec<u8> {
    const PAYLOAD_LEN: usize = 1 + 64 + 32; // scheme byte + sig + pubkey
    let mut out = encode_uleb128(PAYLOAD_LEN as u64);
    out.push(0x00); // Ed25519 scheme flag
    let mut buf = vec![0u8; 64 + 32];
    rng.fill_bytes(&mut buf);
    out.extend(buf);
    out
}

/// Generate a valid `validator-aggregated-signature` in BCS wire form.
///
/// Layout: u64 epoch + 48OCTET bls-sig + BCS-bytes(roaring bitmap).
/// Uses an empty RoaringBitmap so the bitmap deserialization always succeeds.
fn gen_validator_aggregated_signature(rng: &mut StdRng) -> Vec<u8> {
    let mut out = rng.next_u64().to_le_bytes().to_vec(); // epoch u64
    let mut sig = vec![0u8; 48];
    rng.fill_bytes(&mut sig);
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

fn generate(
    rule: &str,
    grammar: &HashMap<String, Expr>,
    overrides: &Overrides,
    rng: &mut StdRng,
) -> Vec<u8> {
    if let Some(f) = overrides.get(rule) {
        return f(rng);
    }
    let expr = grammar
        .get(rule)
        .unwrap_or_else(|| panic!("unknown rule: {rule}"));
    gen_expr(expr, grammar, overrides, rng, 0)
}

fn gen_expr(
    expr: &Expr,
    grammar: &HashMap<String, Expr>,
    overrides: &Overrides,
    rng: &mut StdRng,
    depth: usize,
) -> Vec<u8> {
    let minimal = depth > MAX_DEPTH;
    match expr {
        Expr::Empty => vec![],
        Expr::Concat(parts) => {
            let mut out = Vec::new();
            for p in parts {
                out.extend(gen_expr(p, grammar, overrides, rng, depth));
            }
            out
        }
        Expr::Alt(alts) => {
            let idx = if minimal {
                0
            } else {
                (rng.next_u64() as usize) % alts.len()
            };
            gen_expr(&alts[idx], grammar, overrides, rng, depth)
        }
        Expr::Literal(b) => vec![*b],
        Expr::RuleRef(name) => {
            if let Some(f) = overrides.get(name.as_str()) {
                return f(rng);
            }
            let child = grammar
                .get(name.as_str())
                .unwrap_or_else(|| panic!("unknown rule: {name}"));
            gen_expr(child, grammar, overrides, rng, depth + 1)
        }
        Expr::Prim(p) => gen_prim(p, rng),
        Expr::Vector(inner) => {
            // Keep vectors small: 0-5 elements normally, 0 in minimal mode
            let count: usize = if minimal {
                0
            } else {
                (rng.next_u32() as usize) % 6
            };
            let mut out = encode_uleb128(count as u64);
            for _ in 0..count {
                out.extend(gen_expr(inner, grammar, overrides, rng, depth));
            }
            out
        }
        Expr::Opt(inner) => {
            let some = !minimal && (rng.next_u32() & 1 == 0);
            if some {
                let mut out = vec![0x01];
                out.extend(gen_expr(inner, grammar, overrides, rng, depth));
                out
            } else {
                vec![0x00]
            }
        }
        Expr::Map(k_expr, v_expr) => {
            let count: usize = if minimal {
                0
            } else {
                (rng.next_u32() as usize) % 4
            };
            let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..count)
                .map(|_| {
                    (
                        gen_expr(k_expr, grammar, overrides, rng, depth),
                        gen_expr(v_expr, grammar, overrides, rng, depth),
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
            let mut bytes = vec![0u8; *n];
            rng.fill_bytes(&mut bytes);
            bytes
        }
    }
}

fn gen_prim(p: &PrimKind, rng: &mut StdRng) -> Vec<u8> {
    match p {
        PrimKind::U8 => (rng.next_u32() as u8).to_le_bytes().to_vec(),
        PrimKind::U16 => (rng.next_u32() as u16).to_le_bytes().to_vec(),
        PrimKind::U32 => rng.next_u32().to_le_bytes().to_vec(),
        PrimKind::U64 => rng.next_u64().to_le_bytes().to_vec(),
        PrimKind::U128 => {
            let lo = rng.next_u64() as u128;
            let hi = rng.next_u64() as u128;
            ((hi << 64) | lo).to_le_bytes().to_vec()
        }
        PrimKind::I64 => (rng.next_u64() as i64).to_le_bytes().to_vec(),
        PrimKind::Bool => vec![rng.next_u32() as u8 & 1],
        PrimKind::Bytes => {
            let len = (rng.next_u32() as usize) % 17; // 0..=16
            let mut out = encode_uleb128(len as u64);
            let mut content = vec![0u8; len];
            rng.fill_bytes(&mut content);
            out.extend(content);
            out
        }
        PrimKind::Str => {
            // Non-empty ASCII identifier (a-z first char, then a-z0-9_).
            // BCS strings are UTF-8; Move Identifier validation requires non-empty
            // strings starting with a letter.  This conservative generation avoids
            // TypeParseError rejections that would mask real format bugs.
            let len = 1 + (rng.next_u32() as usize) % 16; // 1..=16
            let mut out = encode_uleb128(len as u64);
            // First character: always a letter
            out.push(b'a' + (rng.next_u32() as u8 % 26));
            // Remaining characters: letter, digit, or underscore
            for _ in 1..len {
                let ch = match rng.next_u32() % 3 {
                    0 => b'a' + (rng.next_u32() as u8 % 26),
                    1 => b'0' + (rng.next_u32() as u8 % 10),
                    _ => b'_',
                };
                out.push(ch);
            }
            out
        }
    }
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
             BCS_SCHEMA=1 cargo check -p iota-sdk-types --features bcs-schema"
            )
        });
        let grammar = parse_grammar(&content);

        // Rule-level overrides for types whose BCS deserializers apply semantic
        // validation (valid scheme byte, roaring-bitmap magic) beyond the grammar.
        // The override generators are wired into gen_expr so they fire whenever the
        // named rule is referenced at any depth, fixing all cascade types too.
        let mut overrides: Overrides = Default::default();
        overrides.insert("checkpoint-contents", gen_checkpoint_contents);
        overrides.insert("user-signature", gen_user_signature);
        overrides.insert(
            "validator-aggregated-signature",
            gen_validator_aggregated_signature,
        );

        Self {
            grammar,
            overrides,
            rng: StdRng::seed_from_u64(0xdead_beef_cafe_babe),
            failures: Vec::new(),
        }
    }

    /// Generate `$iters` byte sequences conforming to `rule` and assert that
    /// `bcs::from_bytes::<$ty>` accepts each one.
    /// Failures are collected into a vector rather than panicking immediately,
    /// so the full test can run to completion.
    fn check_rule<T: Serialize + DeserializeOwned>(&mut self, rule: &str) {
        const ITERATIONS: usize = 200;
        for i in 0_usize..ITERATIONS {
            let bytes = generate(rule, &self.grammar, &self.overrides, &mut self.rng);
            match bcs::from_bytes::<T>(&bytes) {
                Ok(val) => match bcs::to_bytes(&val) {
                    Ok(round_trip) => {
                        if round_trip != bytes {
                            self.failures
                                .push(format!("Rule '{rule}' iter {i}: round-trip mismatch:\n  original bytes ({} bytes): {bytes:02x?}\n  round-trip bytes ({} bytes): {round_trip:02x?}",
                                    bytes.len(),
                                    round_trip.len(),
                                ));
                            break;
                        }
                    }
                    Err(e) => {
                        self.failures
                            .push(format!("Rule '{rule}' iter {i}: serialization failed: {e}"));
                        break;
                    }
                },
                Err(e) => {
                    self.failures.push(format!(
                        "Rule '{rule}' iter {i}: {e}\n  bytes ({} bytes): {:02x?}",
                        bytes.len(),
                        bytes,
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

    test.check_rule::<ActiveJwk>("active-jwk");
    test.check_rule::<Address>("address");
    test.check_rule::<Argument>("argument");
    test.check_rule::<AuthenticatorStateExpire>("authenticator-state-expire");
    test.check_rule::<AuthenticatorStateUpdateV1>("authenticator-state-update-v1");
    test.check_rule::<Bls12381PublicKey>("bls12381-public-key");
    test.check_rule::<Bls12381Signature>("bls12381-signature");
    test.check_rule::<CancelledTransaction>("cancelled-transaction");
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
    test.check_rule::<Jwk>("jwk");
    test.check_rule::<JwkId>("jwk-id");
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
