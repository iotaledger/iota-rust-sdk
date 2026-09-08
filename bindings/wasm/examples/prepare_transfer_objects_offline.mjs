// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  Ed25519PrivateKey,
  FaucetClient,
  GraphQlClient,
  ObjectFilter,
  PtbArgument,
  TransactionBuilder,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newLocalnet();

const privateKey = Ed25519PrivateKey.random();
const fromAddress = privateKey.publicKey().deriveAddress();
const toAddress = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);

const faucet = FaucetClient.newLocalnet();
await faucet.requestAndWaitForFinalized(fromAddress, client);

const coins = (await client.objects(ObjectFilter.new({ owner: fromAddress })))
  .data;
const [gasCoin, ...toTransfer] = coins;
const objsToTransfer = toTransfer.map((coin) =>
  PtbArgument.objectRef(coin.objectRef()),
);
const gasPrice = (await client.referenceGasPrice()) ?? 100n;

const builder = new TransactionBuilder(fromAddress);
builder.transferObjects(toAddress, objsToTransfer);
builder.gas([gasCoin.objectRef()]).gasPrice(gasPrice).gasBudget(500000000n);

const txn = builder.finish();

console.log("Signing Digest:", txn.signingDigestHex());
console.log("Txn Bytes:", txn.toBase64());

const res = await client.dryRunTransaction(txn);
if (res.error) {
  throw new Error(`Failed to transfer objects: ${res.error}`);
}
console.log("Transfer objects dry run was successful!");
