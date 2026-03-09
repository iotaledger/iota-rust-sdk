// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { generateMnemonic, MnemonicLength } from "../lib";

function main() {
  const mnemonic24 = generateMnemonic(undefined);
  console.log("24 word mnemonic:", mnemonic24);
  const mnemonic12 = generateMnemonic("words12");
  console.log("12 word mnemonic:", mnemonic12);
}

main();
