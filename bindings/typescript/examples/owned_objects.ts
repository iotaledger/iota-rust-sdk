// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Address, ObjectFilter } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();
  const address = Address.zero();
  const objectsPage = await client.objects(ObjectFilter.create({ owner: address }));
  console.log(`Owned objects(${objectsPage.data.length}):`);
  for (const obj of objectsPage.data) {
    console.log(obj.objectId().toHex());
  }
}

main();
