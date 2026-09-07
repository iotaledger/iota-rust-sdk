// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  Ed25519PrivateKey,
  FaucetClient,
  GraphQlClient,
  Identifier,
  PtbArgument,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newLocalnet();

const privateKey = new Ed25519PrivateKey(new Uint8Array(32).fill(9));
const sender = privateKey.publicKey().deriveAddress();

const faucet = FaucetClient.newLocalnet();
await faucet.requestAndWaitForFinalized(sender, client);

const builder = client.transactionBuilder(sender);

const packageAddr = Address.std();
const moduleName = new Identifier("u64");
const functionName = new Identifier("max");

builder.moveCall(
  packageAddr,
  moduleName,
  functionName,
  [PtbArgument.u64(0n), PtbArgument.u64(1000n)],
  [],
  // Assign a name to the result of this command
  ["res0"],
);

builder.moveCall(
  packageAddr,
  moduleName,
  functionName,
  [PtbArgument.u64(1000n), PtbArgument.u64(2000n)],
  [],
  ["res1"],
);

builder.splitCoins(
  PtbArgument.gas(),
  // Use the assigned results of previous commands to use as arguments
  [PtbArgument.assigned("res0"), PtbArgument.assigned("res1")],
  // For nested results, an array can be used to name them
  ["coin0", "coin1"],
);

// Use assigned results as arguments
builder.transferObjects(sender, [
  PtbArgument.assigned("coin0"),
  PtbArgument.assigned("coin1"),
]);

const txn = await builder.finish();

console.log("Signing Digest:", txn.signingDigestHex());
console.log("Txn Bytes:", txn.toBase64());

const res = await client.dryRunTransaction(txn, false);
if (res.error) {
  throw new Error(`Failed to send tx: ${res.error}`);
}

console.log("Tx dry run was successful!");
