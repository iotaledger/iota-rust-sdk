// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, ObjectFilter, uniffiInitAsync } from "iota-sdk-wasm";

await uniffiInitAsync();

const client = GraphQlClient.newTestnet();

const stakedIotas = await client.objects(
  new ObjectFilter({ typeTag: "0x3::staking_pool::StakedIota" }),
);

if (stakedIotas.data.length === 0) {
  console.log("No StakedIota objects found");
} else {
  console.log("StakedIota object IDs:");
  for (const stakedIota of stakedIotas.data) {
    console.log(stakedIota.objectId().toHex());
  }
}
