// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, hexEncode, ObjectId, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const objectId = ObjectId.fromHex(
  "0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755",
);

const obj = await client.object(objectId);
if (obj === null) {
  throw new Error("missing object");
}

console.log("Object ID:", obj.id().toHex());
console.log("Version:", obj.version());
console.log("Previous transaction:", obj.previousTransaction().toBase58());
console.log("Owner:", obj.owner());
console.log("Storage rebate:", obj.storageRebate());
console.log("Type:", obj.objectType());
console.log("BCS bytes:", hexEncode(obj.asStruct().contents));
