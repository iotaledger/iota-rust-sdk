// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { Address, GraphQlClient, PtbArgument, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const fromAddress = Address.fromHex(
  "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
);
const toAddress = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);

// A coin of type
// 0xfce9c14e5f0c2b65787debb8145a33a4a2fc83152e8939000b862e174bc86bb8::cert::CERT
const coinId = PtbArgument.objectIdFromHex(
  "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2",
);

const builder = client.transactionBuilder(fromAddress);
builder.sendCoins([coinId], toAddress, PtbArgument.u64(50000000000n));

const txn = await builder.finish();
console.log("Signing Digest:", txn.signingDigestHex());
console.log("Txn Bytes:", txn.toBase64());

const res = await builder.dryRun();
if (res.error) {
  throw new Error(`Failed to send coins: ${res.error}`);
}
console.log("Send coins dry run was successful!");
