// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  generateMnemonic,
  MnemonicLength,
  uniffiInitAsync,
} from "@iota/sdk-wasm";

await uniffiInitAsync();

console.log("24 word mnemonic:", generateMnemonic(undefined));
console.log("12 word mnemonic:", generateMnemonic(MnemonicLength.Words12));
