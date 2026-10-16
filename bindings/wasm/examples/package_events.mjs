// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlDirection,
  GraphQlEventFilter,
  GraphQlClient,
  GraphQlPaginationFilter,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const events = await client.events(
  GraphQlEventFilter.new({
    eventType:
      "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent",
  }),
  GraphQlPaginationFilter.new({
    direction: GraphQlDirection.Forward,
    limit: 10,
  }),
);

for (const event of events.data) {
  console.log(`Type: ${event.moveType}`);
  console.log(`Sender: ${event.sender}`);
  console.log(`Module: ${event.module}`);
  console.log(`JSON: ${event.json}`);
}
