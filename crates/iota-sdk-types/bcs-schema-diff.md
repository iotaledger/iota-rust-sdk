## A. Structural / variant mismatches (different bytes on the wire)

### A3. `move-call.type-arguments` uses the wrong element type

[bcs-schema.abnf:271-275](crates/iota-sdk-types/bcs-schema.abnf#L271-L275)

- YAML `ProgrammableMoveCall.type_arguments`: `SEQ<TypeInput>`.
- ABNF: `(size *type-tag)`.

### A4. `make-move-vector.type-` uses the wrong element type

[bcs-schema.abnf:265-266](crates/iota-sdk-types/bcs-schema.abnf#L265-L266)

- YAML `Command::MakeMoveVec`: `TUPLE<OPTION<TypeInput>, SEQ<Argument>>`.
- ABNF: `(%d00 / %d01 type-tag) (size *argument)`.

(Bytes happen to coincide in A3/A4 because `TypeInput` and `TypeTag` share tag numbering and both trail with a `Struct(Input)` whose shape matches `StructTag`. But the ABNF nominally describes a different type — it never defines `type-input` / `struct-input`.)

### A5. `package-upgrade-error` %d03 (`DigestDoesNotMatch`)

[bcs-schema.abnf:326](crates/iota-sdk-types/bcs-schema.abnf#L326)

- YAML: `digest: SEQ<U8>` (variable-length bytes).
- ABNF: `digest` (= `%d32 32OCTET`, forced 32 bytes).

The ABNF is strictly stricter than BCS would allow here.

### A6. `checkpoint-transaction.transaction`: length-1 baked in

[bcs-schema.abnf:96](crates/iota-sdk-types/bcs-schema.abnf#L96)

ABNF hard-codes the sequence length of `SenderSignedData` with a literal `%d01`:

```
checkpoint-transaction = %d01 intent-signed-transaction ...
```

YAML `SenderSignedData` is `NEWTYPESTRUCT: SEQ<SenderSignedTransaction>`, i.e., any length. ABNF is stricter.

### A7. Fixed-length vs. length-prefixed bytes

- `digest` ([line 138](crates/iota-sdk-types/bcs-schema.abnf#L138)): `%d32 32OCTET` — fixed. YAML `Digest` is `NEWTYPESTRUCT: BYTES` (variable).
- `bls12381-public-key` ([line 11](crates/iota-sdk-types/bcs-schema.abnf#L11)): `%d96 96OCTET` — fixed. YAML `AuthorityPublicKeyBytes` is `NEWTYPESTRUCT: BYTES` (variable).

Both ABNF rules force one specific length; YAML nominally permits any length.

### A8. `intent` sub-bytes are enumerated in ABNF, free `U8` in YAML

- YAML `Intent { scope: U8, version: U8, app_id: U8 }` — any byte.
- ABNF restricts to specific values:
  - [bcs-schema.abnf:248-257](crates/iota-sdk-types/bcs-schema.abnf#L248-L257) `intent-scope` ∈ {0..9}
  - [bcs-schema.abnf:263](crates/iota-sdk-types/bcs-schema.abnf#L263) `intent-version` = `%d00` (only V0)
  - [bcs-schema.abnf:245-246](crates/iota-sdk-types/bcs-schema.abnf#L245-L246) `intent-app-id` ∈ {0, 1}

## B. Types present in ABNF but not in YAML

### B2. Standalone `validator-committee` rule

[bcs-schema.abnf:453-454](crates/iota-sdk-types/bcs-schema.abnf#L453-L454)

`validator-committee = u64 (size *validator-committee-member)` has no standalone YAML counterpart (YAML inlines the pairs in `EndOfEpochData.nextEpochCommittee`).

## C. Types present in YAML but not in ABNF

All of the following are YAML-only:

- `ActiveJwk`, `AuthenticatorStateExpire`, `AuthenticatorStateUpdateV1` (consistent with A1/A2 gaps)
- `PublicKey`, `CompressedSignature`, `MultiSig`, `MultiSigPublicKey` (ABNF treats all signatures as opaque `user-signature = bytes`, [line 447](crates/iota-sdk-types/bcs-schema.abnf#L447))
- `TypeInput`, `StructInput` (consequence of A3/A4)
- `ExecutionData`, `FullCheckpointContents`
- `ObjectInfoRequestKind`
- `DeleteKind` (appears unreferenced in YAML itself)
- `TypedStoreError` (SDK-internal error type)

## E. YAML NEWTYPESTRUCT wrappers that ABNF inlines (same bytes)

ABNF doesn't give these names; it substitutes the underlying rule everywhere they'd appear:

- `ObjectID` → `address` (actually defined as `object-id = address`, line 305)
- `SequenceNumber`, `ProtocolVersion`, `RandomnessRound` → `u64`
- `TransactionDigest`, `CheckpointDigest`, `CheckpointContentsDigest`, `ObjectDigest`, `ConsensusCommitDigest`, `EffectsAuxDataDigest`, `TransactionEffectsDigest`, `TransactionEventsDigest` → `digest`
- `ECMHLiveObjectSetDigest` (STRUCT with one `digest` field) → `digest` (line 74)
- `MoveObjectType` / `MoveObjectType_` → `compressed-struct-tag`
- `TransactionEvents` (struct with one field `data: SEQ<Event>`) → `(size *event)` (line 379)
- `EmptySignInfo` (empty struct) → silently omitted in `signed-checkpoint-summary` and the `checkpoint-transaction` transaction slot

## Summary of actionable gaps in the ABNF

1. **Add** `%d04` (`AuthenticatorStateCreate`) and `%d05 authenticator-state-expire` to `end-of-epoch-transaction-kind`, plus the backing `authenticator-state-expire` and supporting `authenticator-state-update-v1`, `active-jwk`, `jwk`, `jwk-id` rules (A1).
2. **Attach a payload** to `transaction-kind` `%d03` (A2) — or confirm this variant is actually deprecated/empty in the SDK and the YAML is stale.
3. **Introduce `type-input` / `struct-input`** rules and use them in `move-call.type-arguments` and `make-move-vector.type-` (A3, A4).
4. **Widen `package-upgrade-error` `%d03`** from `digest` to `bytes` (A5).
5. Decide whether `checkpoint-transaction` truly requires length-1 `SenderSignedData` (A6) — if not, replace `%d01 intent-signed-transaction` with `(size *intent-signed-transaction)`.
6. Decide whether `digest` and `bls12381-public-key` should be fixed-length or length-prefixed `bytes` (A7).
7. **Remove or port** the `execution-time-observation*` family (B1) — either it's missing from YAML or it's obsolete in ABNF.
8. Cross-check the naming renames in section D against whichever spec you consider canonical.
