// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();

  // Get current epoch
  const currentEpoch = await client.epoch();
  if (currentEpoch === undefined) {
    throw new Error("missing current epoch");
  }

  console.log(`Current epoch: ${currentEpoch.epochId}`);
  console.log(`Current epoch start time: ${currentEpoch.startTimestamp}`);

  // Get previous epoch
  const previousEpochId = currentEpoch.epochId - 1n;
  const previousEpoch = await client.epoch(previousEpochId);
  if (previousEpoch === undefined) {
    throw new Error("missing previous epoch");
  }

  console.log(`Previous epoch: ${previousEpoch.epochId}`);
  if (previousEpoch.totalStakeRewards !== undefined) {
    console.log(`Previous epoch stake rewards: ${previousEpoch.totalStakeRewards}`);
  }
}

main();
