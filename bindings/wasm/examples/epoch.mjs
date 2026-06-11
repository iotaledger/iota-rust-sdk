// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const currentEpoch = await client.epoch();
if (currentEpoch === null) {
  throw new Error("missing current epoch");
}

console.log(`Current epoch: ${currentEpoch.epochId}`);
console.log(`Current epoch start time: ${currentEpoch.startTimestamp}`);

const previousEpochId = currentEpoch.epochId - 1n;
const previousEpoch = await client.epoch(previousEpochId);
if (previousEpoch === null) {
  throw new Error("missing previous epoch");
}

console.log(`Previous epoch: ${previousEpoch.epochId}`);
if (previousEpoch.totalStakeRewards !== null) {
  console.log(
    `Previous epoch stake rewards: ${previousEpoch.totalStakeRewards}`,
  );
}
