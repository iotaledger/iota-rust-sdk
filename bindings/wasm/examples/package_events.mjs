// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Direction,
  EventFilter,
  GraphQlClient,
  PaginationFilter,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const events = await client.events(
  EventFilter.new({
    eventType:
      "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent",
  }),
  PaginationFilter.new({ direction: Direction.Forward, limit: 10 }),
);

for (const event of events.data) {
  console.log(`Type: ${event.type}`);
  console.log(`Sender: ${event.sender.toHex()}`);
  console.log(`Module: ${event.module}`);
  console.log(`JSON: ${event.json}`);
}
