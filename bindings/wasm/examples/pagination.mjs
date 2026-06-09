// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  Direction,
  GraphQlClient,
  ObjectFilter,
  PaginationFilter,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();
const address = Address.fromHex(
  "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
);

const allObjects = [];
let nextCursor = undefined;
while (true) {
  console.log(`Fetching page with cursor: ${nextCursor}`);
  const page = await client.objects(
    ObjectFilter.new({ owner: address }),
    // Limit to 1 to demonstrate pagination
    PaginationFilter.new({
      direction: Direction.Forward,
      cursor: nextCursor,
      limit: 1,
    }),
  );
  allObjects.push(...page.data);
  if (page.pageInfo.hasNextPage) {
    nextCursor = page.pageInfo.endCursor;
  } else {
    break;
  }
}
console.log(`${allObjects.length} objects fetched:`);
for (const obj of allObjects) {
  console.log(obj.id().toHex());
}
