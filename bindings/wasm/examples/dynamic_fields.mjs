// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { Address, GraphQlClient, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();
const parentObjectId = Address.fromHex(
  "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec",
);

const page = await client.dynamicFields(parentObjectId);
console.log("Page size:", page.data.length);
if (page.data.length > 0) {
  console.log("First field name:\n", page.data[0].name);
  console.log("First field value:\n", page.data[0].valueAsJson);
}
