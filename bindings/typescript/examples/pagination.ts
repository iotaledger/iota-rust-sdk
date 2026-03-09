// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Address, ObjectFilter, PaginationFilter, Direction } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();
  const address = Address.fromHex(
    "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
  );

  const allObjects: any[] = [];
  let nextCursor: string | undefined = undefined;
  while (true) {
    console.log(`Fetching page with cursor: ${nextCursor}`);
    const page = await client.objects(
      ObjectFilter.create({ owner: address }),
      // Limit to 1 to demonstrate pagination
      PaginationFilter.create({ direction: "forward", cursor: nextCursor, limit: 1 }),
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
    console.log(obj.objectId().toHex());
  }
}

main();
