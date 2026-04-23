## A. Structural / variant mismatches (different bytes on the wire)

### A6. `checkpoint-transaction.transaction`: length-1 baked in

[bcs-schema.abnf:96](crates/iota-sdk-types/bcs-schema.abnf#L96)

ABNF hard-codes the sequence length of `SenderSignedData` with a literal `%d01`:

```
checkpoint-transaction = %d01 intent-signed-transaction ...
```

YAML `SenderSignedData` is `NEWTYPESTRUCT: SEQ<SenderSignedTransaction>`, i.e., any length. ABNF is stricter.

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

- `PublicKey`, `CompressedSignature`, `MultiSig`, `MultiSigPublicKey` (ABNF treats all signatures as opaque `user-signature = bytes`, [line 447](crates/iota-sdk-types/bcs-schema.abnf#L447))
- `ExecutionData`, `FullCheckpointContents`
- `ObjectInfoRequestKind`
- `DeleteKind` (appears unreferenced in YAML itself)
- `TypedStoreError` (SDK-internal error type)

## E. YAML NEWTYPESTRUCT wrappers that ABNF inlines (same bytes)

ABNF doesn't give these names; it substitutes the underlying rule everywhere they'd appear:

- `SequenceNumber`, `ProtocolVersion`, `RandomnessRound` → `u64`
- `ECMHLiveObjectSetDigest` (STRUCT with one `digest` field) → `digest` (line 74)
- `TransactionEvents` (struct with one field `data: SEQ<Event>`) → `(size *event)` (line 379)
- `EmptySignInfo` (empty struct) → silently omitted in `signed-checkpoint-summary` and the `checkpoint-transaction` transaction slot

## Summary of actionable gaps in the ABNF

4. **Widen `package-upgrade-error` `%d03`** from `digest` to `bytes` (A5).
5. Decide whether `checkpoint-transaction` truly requires length-1 `SenderSignedData` (A6) — if not, replace `%d01 intent-signed-transaction` with `(size *intent-signed-transaction)`.
