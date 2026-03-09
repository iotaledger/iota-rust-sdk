// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient } from "@iota/sdk";

async function main() {
  const client = GraphQlClient.newTestnet();

  const chainId = await client.chainId();
  console.log("Chain ID:", chainId);
}

main();
