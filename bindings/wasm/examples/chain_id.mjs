// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient } from "./_iota_sdk.mjs";

const client = GraphQlClient.newTestnet();
const chainId = await client.chainId();
console.log("Chain ID:", chainId);
