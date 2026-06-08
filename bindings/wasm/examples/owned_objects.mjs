// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  GraphQlClient,
  ObjectFilter,
  uniffiInitAsync,
} from "@iota/sdk-wasm";

await uniffiInitAsync();

const client = GraphQlClient.newTestnet();
const address = Address.zero();
const objectsPage = await client.objects(ObjectFilter.new({ owner: address }));
console.log(`Owned objects(${objectsPage.data.length}):`);
for (const obj of objectsPage.data) {
  console.log(obj.id().toHex());
}
