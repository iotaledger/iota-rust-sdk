// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Tail transactions as they are executed, over a GraphQL subscription.
//
// Unlike the paginated queries, a subscription never ends on its own: it is
// pulled one update at a time and stopped with `cancel`. Cancelling unblocks a
// pending `next`, which is what keeps the example from waiting forever on a
// network that produces nothing.

import {
  GraphQlClient,
  SubscriptionTransactionFilter,
  TransactionBlockKindInput,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const DEADLINE_MS = 60_000;

const client = GraphQlClient.newLocalnet();
const subscription = await client.transactionsSubscription(
  SubscriptionTransactionFilter.new({
    kind: TransactionBlockKindInput.ProgrammableTx,
  }),
);

const watchdog = setTimeout(() => subscription.cancel(), DEADLINE_MS);

try {
  console.log("Waiting for a transaction...");
  while (true) {
    const update = await subscription.next();
    if (update === undefined) {
      throw new Error(`No transaction observed within ${DEADLINE_MS}ms`);
    }

    if (update.tag === "Transaction") {
      const { transaction } = update.inner.transaction;
      console.log(`Digest: ${transaction.digest()}`);
      console.log(`Sender: ${transaction.sender().toHex()}`);
      break;
    } else {
      // Delivery recovers on its own; items in the gap may be missed.
      console.log(`Interrupted: ${update.inner.message}`);
    }
  }
} finally {
  clearTimeout(watchdog);
  subscription.cancel();
}
