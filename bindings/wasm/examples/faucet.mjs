// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { Address, FaucetClient, initAsync } from "@iota/sdk-wasm";

await initAsync();

const address = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);
const faucetClient = FaucetClient.newLocalnet();
const faucetReceipt = await faucetClient.requestAndWait(address);
if (faucetReceipt) {
  console.log("Faucet receipt:");
  for (const coin of faucetReceipt.sent) {
    console.log(
      `  Coin ID: ${coin.id.toHex()}, Amount: ${coin.amount}, Digest: ${coin.transferTxDigest.toBase58()}`,
    );
  }
} else {
  console.log("Faucet receipt: None");
}
