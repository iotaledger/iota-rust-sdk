// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Query } from "./_iota_sdk.mjs";

const client = GraphQlClient.newTestnet();

const queryStr = `
  query getLatestIotaSystemState {
    epoch {
      epochId
      startTimestamp
      endTimestamp
      referenceGasPrice
      safeMode {
        enabled
        gasSummary {
          computationCost
          computationCostBurned
          nonRefundableStorageFee
          storageCost
          storageRebate
        }
      }
      storageFund {
        nonRefundableBalance
        totalObjectStorageRebates
      }
      systemStateVersion
      iotaTotalSupply
      iotaTreasuryCapId
      systemParameters {
        minValidatorCount
        maxValidatorCount
        minValidatorJoiningStake
        durationMs
        validatorLowStakeThreshold
        validatorLowStakeGracePeriod
        validatorVeryLowStakeThreshold
      }
      protocolConfigs {
        protocolVersion
      }
      validatorSet {
        inactivePoolsSize
        pendingActiveValidatorsSize
        stakingPoolMappingsSize
        validatorCandidatesSize
        pendingRemovals
        totalStake
      }
    }
  }
`;

const res = await client.runQuery(new Query({ query: queryStr }));
console.log(res);
