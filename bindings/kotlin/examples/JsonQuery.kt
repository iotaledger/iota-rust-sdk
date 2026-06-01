// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.Query
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    val client = GraphQlClient.newTestnet()

    val queryStr =
        """
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

    val query = Query(queryStr)
    val res = client.runQuery(query)
    println(res)
}
