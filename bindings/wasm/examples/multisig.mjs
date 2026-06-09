// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// 2-of-3 Ed25519 multisig example.
//
// Derives 3 keypairs from a mnemonic at indices 0, 1, 2, creates a multisig
// committee with threshold 2, funds the multisig address via faucet, builds
// a send_iota transaction, signs with only 2 of the 3 keys, aggregates,
// and executes.
//
// Requires a running localnet (`iota start --force-regenesis`).

import {
  Address,
  Ed25519PrivateKey,
  FaucetClient,
  GraphQlClient,
  hexEncode,
  MultisigAggregator,
  MultisigCommittee,
  MultisigMember,
  PtbArgument,
  SimpleKeypair,
  TransactionBuilder,
  initAsync,
  UserSignature,
} from "@iota/sdk-wasm";

await initAsync();

const MNEMONIC =
  "round attack kitchen wink winter music trip tiny nephew hire orange what";

const amount = 1000n;
const recipientAddress = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);

// 1. Derive 3 Ed25519 keypairs from mnemonic at indices 0, 1, 2.
const key0 = Ed25519PrivateKey.fromMnemonic(MNEMONIC, 0n);
const key1 = Ed25519PrivateKey.fromMnemonic(MNEMONIC, 1n);
const key2 = Ed25519PrivateKey.fromMnemonic(MNEMONIC, 2n);

// 2. Wrap in SimpleKeypair to access MultisigMemberPublicKey.
const kp0 = SimpleKeypair.fromEd25519(key0);
const kp1 = SimpleKeypair.fromEd25519(key1);
const kp2 = SimpleKeypair.fromEd25519(key2);

// 3. Build multisig committee: threshold=2, each member weight=1.
const committee = new MultisigCommittee(
  [
    new MultisigMember(kp0.publicKey(), 1),
    new MultisigMember(kp1.publicKey(), 1),
    new MultisigMember(kp2.publicKey(), 1),
  ],
  2,
);

// 4. Derive multisig address.
const multisigAddress = committee.deriveAddress();
console.log(`Multisig address: ${multisigAddress.toHex()}`);

const client = GraphQlClient.newLocalnet();

// 5. Fund the multisig address.
const faucet = FaucetClient.newLocalnet();
await faucet.requestAndWaitForFinalized(multisigAddress, client);

// 6. Build a send_iota transaction.
const builder = new TransactionBuilder(multisigAddress).withClient(client);
builder.sendIota(recipientAddress, PtbArgument.u64(amount));
const txn = await builder.finish();

const dryRunResult = await client.dryRunTx(txn);
if (dryRunResult.error) {
  throw new Error(`Dry run failed: ${dryRunResult.error}`);
}

// 7. Sign with key0 and key1 (2-of-3 threshold).
const sig0 = kp0.signTransaction(txn);
const sig1 = kp1.signTransaction(txn);

// 8. Aggregate signatures.
let aggregator = MultisigAggregator.newWithTransaction(committee, txn);
aggregator = aggregator.withSignature(sig0);
aggregator = aggregator.withSignature(sig1);
const aggSig = aggregator.finish();

// 9. Execute.
const userSignature = UserSignature.newMultisig(aggSig);
const effects = await client.executeTx([userSignature], txn);

console.log(`Digest: ${hexEncode(effects.digest().toBytes())}`);
console.log(`Transaction status: ${effects.asV1().status}`);
console.log(`Effects: ${effects.asV1()}`);
