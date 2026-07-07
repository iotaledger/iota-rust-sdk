// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Decode `StakedIota` objects into typed JavaScript values.
//
// The GraphQL client returns each object's contents as raw BCS bytes. A single
// `StakedIota.tryFromObject(obj)` call gives typed, named-field access to
// id / poolId / stakeActivationEpoch / principal.

import {
  GraphQlClient,
  ObjectFilter,
  StakedIota,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const page = await client.objects(
  ObjectFilter.new({ typeTag: "0x3::staking_pool::StakedIota" }),
);

if (page.data.length === 0) {
  console.log("No StakedIota objects on testnet right now.");
} else {
  console.log(`Decoded ${page.data.length} StakedIota object(s):\n`);
  let totalPrincipal = 0n;
  for (const obj of page.data) {
    const staked = StakedIota.tryFromObject(obj);
    totalPrincipal += staked.principal();
    console.log(`- id:               ${staked.id().toHex()}`);
    console.log(`  pool_id:          ${staked.poolId().toHex()}`);
    console.log(`  stake_activation_epoch: ${staked.stakeActivationEpoch()}`);
    console.log(`  principal (nanos): ${staked.principal()}`);
    console.log();
  }

  console.log(`Total principal across page: ${totalPrincipal} nanos`);
}
