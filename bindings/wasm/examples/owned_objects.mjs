// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  GraphQlClient,
  GraphQlObjectFilter,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();
const address = Address.zero();
const objectsPage = await client.objects(
  GraphQlObjectFilter.new({ owner: address }),
);
console.log(`Owned objects(${objectsPage.data.length}):`);
for (const obj of objectsPage.data) {
  console.log(obj.id().toHex());
}
