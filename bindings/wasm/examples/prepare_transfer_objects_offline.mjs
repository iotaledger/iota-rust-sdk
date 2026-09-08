// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  GraphQlClient,
  ObjectId,
  PtbArgument,
  TransactionBuilder,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const fromAddress = Address.fromHex(
  "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
);
const toAddress = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);
const objIds = [
  ObjectId.fromHex(
    "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
  ),
  ObjectId.fromHex(
    "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc",
  ),
  ObjectId.fromHex(
    "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2",
  ),
];

const objsToTransfer = [];
for (const objId of objIds) {
  const obj = await client.object(objId);
  if (obj === null) {
    throw new Error(`Missing object: ${objId}`);
  }
  objsToTransfer.push(PtbArgument.objectRef(obj.objectRef()));
}

const gasCoinId = ObjectId.fromHex(
  "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
);
const gasCoin = await client.object(gasCoinId);
if (gasCoin === null) {
  throw new Error(`Missing gas coin: ${gasCoinId}`);
}
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
