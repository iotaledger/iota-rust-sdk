// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// Demonstrates converting a Transaction to and from JSON.

import {
  Transaction,
  transactionFromJson,
  transactionToJson,
  uniffiInitAsync,
} from "iota-sdk-wasm";

await uniffiInitAsync();

const txBytesBase64 =
  "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA=";

const transaction = Transaction.fromBase64(txBytesBase64);

const json = transactionToJson(transaction);
console.log(`Transaction as JSON:\n${json}`);

const parsedTransaction = transactionFromJson(json);
console.log(`Parsed transaction back from JSON: ${parsedTransaction}`);
