# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    query_str = """
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
    """

    query = Query(query_string=query_str)
    res = await client.run_query(query)
    print(res)


if __name__ == "__main__":
    asyncio.run(main())
