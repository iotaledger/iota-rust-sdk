// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Decode `StakedIota` objects into typed JavaScript values.
//
// The GraphQL client returns each object's contents as raw BCS bytes. A single
// `StakedIota.tryFromObject(obj)` call gives typed, named-field access to
// id / poolId / stakeActivationEpoch / principal.

import {
  Direction,
  GraphQlClient,
  ObjectFilter,
  PaginationFilter,
  StakedIota,
  TransactionsFilter,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

// Filtering objects by type alone scans every object on the network, which the
// GraphQL server rejects with a timeout. Pick a recent staker and filter by
// owner as well, so only that address' objects are looked at.
const stakers = await client.transactions(
  TransactionsFilter.new({ function: "0x3::iota_system::request_add_stake" }),
  PaginationFilter.new({ direction: Direction.Backward, limit: 1 }),
);
const staker = stakers.data.at(-1)?.transaction.sender();

if (staker === undefined) {
  console.log("No staking transactions on testnet right now.");
} else {
  console.log(`Latest staker: ${staker.toHex()}\n`);

  const page = await client.objects(
    ObjectFilter.new({
      typeTag: "0x3::staking_pool::StakedIota",
      owner: staker,
    }),
  );

  if (page.data.length === 0) {
    console.log(`No StakedIota objects owned by ${staker.toHex()} right now.`);
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
}
