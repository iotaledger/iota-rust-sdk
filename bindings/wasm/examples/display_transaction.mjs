// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// Demonstrates printing types as human-readable text. Object types offer a
// `toDisplayString()` method, record types a `<type>ToDisplayString()` function.

import { Transaction, gasPaymentToDisplayString, initAsync } from "@iota/sdk-wasm";

await initAsync();

// A sample transaction in base64 format
const txBytesBase64 =
  "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA=";

const transaction = Transaction.fromBase64(txBytesBase64);
console.log(transaction.toDisplayString());

console.log(gasPaymentToDisplayString(transaction.gasPayment()));
