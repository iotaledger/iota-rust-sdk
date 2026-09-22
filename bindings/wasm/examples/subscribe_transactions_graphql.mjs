// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Tail transactions as they are executed, over a GraphQL subscription.
//
// Unlike the paginated queries, a subscription never ends on its own: it is
// pulled one update at a time and stopped with `cancel`. Cancelling unblocks a
// pending `next`, which is what keeps the example from waiting forever on a
// network that produces nothing.

import {
  Address,
  Ed25519PrivateKey,
  FaucetClient,
  GraphQlClient,
  PtbArgument,
  SubscriptionTransactionFilter,
  UserSignature,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const DEADLINE_MS = 60_000;
const amount = 1000n;
const recipientAddress = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);

const privateKey = Ed25519PrivateKey.random();
const senderAddress = privateKey.publicKey().deriveAddress();
console.log(`Sender address: ${senderAddress.toHex()}`);

const client = GraphQlClient.newLocalnet();

const faucet = FaucetClient.newLocalnet();
const receipt = await faucet.requestAndWaitForFinalized(senderAddress, client);
if (!receipt || receipt.sent.length === 0) {
  throw new Error("Faucet did not fund the sender");
}

// Any of the funding digests will do: the transaction below is executed after
// all of them, and the sender filter keeps the faucet's own transactions out of
// the stream.
const startAfter = receipt.sent[0].transferTxDigest.toBase58();

const subscription = await client.transactionsSubscription(
  SubscriptionTransactionFilter.new({ signingAddress: senderAddress }),
  startAfter,
);

const watchdog = setTimeout(() => subscription.cancel(), DEADLINE_MS);

try {
  const builder = client.transactionBuilder(senderAddress);
  builder.sendIota(recipientAddress, PtbArgument.u64(amount));
  const txn = await builder.finish();

  const signature = privateKey.trySignSimple(txn.signingDigest());
  const effects = await client.executeTransaction(
    [UserSignature.newSimple(signature)],
    txn,
  );
  console.log(`Executed: ${effects.digest().toBase58()}`);

  console.log("Waiting for a transaction...");
  while (true) {
    const update = await subscription.next();
    if (update === undefined) {
      throw new Error(`No transaction observed within ${DEADLINE_MS}ms`);
    }

    if (update.tag === "Transaction") {
      const { transaction } = update.inner.transaction;
      console.log(`Digest: ${transaction.digest().toBase58()}`);
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
