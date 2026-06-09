// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Transaction, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const txBytesBase64 =
  "AAABACAAAKSYS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAEBAQABAADaGCDt9pPuMrVymQe5suyOZJgO6MAIwX6Jz7Tl7NchUQHclW3om5FOan+9g8rr78jskb4SB2Z+pVdjhjkaqCRJzPC6fSAAAAAAILFkUl8sWJyphiT+5+p5Rev6nLCp6DDtMQTNwLSMcOHw2hgg7faT7jK1cpkHubLsjmSYDujACMF+ic+05ezXIVHoAwAAAAAAAICEHgAAAAAAAA==";
const transaction = Transaction.fromBase64(txBytesBase64);

const res = await client.dryRunTx(transaction);
if (res.error) {
  throw new Error(`Dry run failed: ${res.error}`);
}

console.log("Dry run was successful!");
console.log(`Dry run result: ${res}`);
