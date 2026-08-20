// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  Ed25519PrivateKey,
  FaucetClient,
  GraphQlClient,
  hexEncode,
  PtbArgument,
  initAsync,
  UserSignature,
} from "@iota/sdk-wasm";

await initAsync();

// Amount to send in nanos
const amount = 1000n;
const recipientAddress = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);

const privateKey = new Ed25519PrivateKey(new Uint8Array(32));
const publicKey = privateKey.publicKey();
const senderAddress = publicKey.deriveAddress();
console.log(`Sender address: ${senderAddress.toHex()}`);

const client = GraphQlClient.newLocalnet();

// Request funds from faucet
const faucet = FaucetClient.newLocalnet();
await faucet.requestAndWaitForFinalized(senderAddress, client);

const builder = client.transactionBuilder(senderAddress);
builder.sendIota(recipientAddress, PtbArgument.u64(amount));
const txn = await builder.finish();

const dryRunResult = await client.dryRunTx(txn);
if (dryRunResult.error) {
  throw new Error(`Dry run failed: ${dryRunResult.error}`);
}

const signature = privateKey.trySignSimple(txn.signingDigest());
const userSignature = UserSignature.newSimple(signature);

const effects = await client.executeTx([userSignature], txn);

console.log(`Digest: ${hexEncode(effects.digest().toBytes())}`);
console.log(`Transaction status: ${effects.asV1().status()}`);
console.log(`Effects: ${effects.asV1()}`);
