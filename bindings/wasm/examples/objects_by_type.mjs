// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, ObjectFilter, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const coins = await client.objects(
  ObjectFilter.new({ typeTag: "0x2::coin::Coin<0x2::iota::IOTA>" }),
);

if (coins.data.length === 0) {
  console.log("No IOTA coin objects found");
} else {
  console.log("IOTA coin object IDs:");
  for (const coin of coins.data) {
    console.log(coin.id().toHex());
  }
}
