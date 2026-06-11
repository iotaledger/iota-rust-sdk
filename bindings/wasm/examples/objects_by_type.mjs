// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, ObjectFilter, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const stakedIotas = await client.objects(
  ObjectFilter.new({ typeTag: "0x3::staking_pool::StakedIota" }),
);

if (stakedIotas.data.length === 0) {
  console.log("No StakedIota objects found");
} else {
  console.log("StakedIota object IDs:");
  for (const stakedIota of stakedIotas.data) {
    console.log(stakedIota.id().toHex());
  }
}
