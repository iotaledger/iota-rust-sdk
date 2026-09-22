// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// Demonstrates converting a Transaction to and from JSON.

import { Transaction, initAsync } from "@iota/sdk-wasm";

await initAsync();

// A sample transaction in base64 format
const txBytesBase64 =
  "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA=";

// Parse the transaction from base64
const transaction = Transaction.fromBase64(txBytesBase64);

// Convert the transaction to JSON
const json = transaction.toJson();
console.log(`Transaction as JSON:\n${json}`);

// Convert the JSON back to a transaction
const parsedTransaction = Transaction.fromJson(json);
console.log(`Parsed transaction back from JSON: ${parsedTransaction}`);
