// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Address } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();

  const address = Address.fromHex(
    "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
  );

  const coins = await client.coins(address);
  for (const coin of coins.data) {
    console.log(
      `Coin = ${coin.id().toHex()}, Coin Type = ${coin.coinType().asStructTag()}, Balance = ${coin.balance()}`,
    );
  }

  const balance = await client.balance(address);
  console.log(`Total Balance = ${balance}`);
}

main();
