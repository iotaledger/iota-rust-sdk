// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Query, initAsync } from "@iota/sdk-wasm";

await initAsync();

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
        activeValidators {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            ...RPC_VALIDATOR_FIELDS
          }
        }
        committeeMembers {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            ...RPC_VALIDATOR_FIELDS
          }
        }
        inactivePoolsSize
        pendingActiveValidatorsSize
        stakingPoolMappingsSize
        validatorCandidatesSize
        pendingRemovals
        totalStake
        stakingPoolMappingsId
        pendingActiveValidatorsId
        validatorCandidatesId
        inactivePoolsId
      }
    }
  }

  fragment RPC_VALIDATOR_FIELDS on Validator {
    address {
      address
    }
    credentials {
      authorityPubKey
      networkPubKey
      protocolPubKey
      proofOfPossession
      netAddress
      p2PAddress
      primaryAddress
    }
    nextEpochCredentials {
      authorityPubKey
      networkPubKey
      protocolPubKey
      proofOfPossession
      netAddress
      p2PAddress
      primaryAddress
    }
    name
    description
    imageUrl
    projectUrl
    operationCap {
      address
    }
    stakingPoolId
    exchangeRatesTable {
      address
    }
    exchangeRatesSize
    stakingPoolActivationEpoch
    stakingPoolIotaBalance
    rewardsPool
    poolTokenBalance
    pendingStake
    pendingTotalIotaWithdraw
    pendingPoolTokenWithdraw
    votingPower
    gasPrice
    commissionRate
    nextEpochStake
    nextEpochGasPrice
    nextEpochCommissionRate
    atRisk
    reportRecords {
      nodes {
        address
      }
    }
    apy
  }
`;

const res = await client.runQuery(Query.new({ queryString: queryStr }));
console.log(res);
