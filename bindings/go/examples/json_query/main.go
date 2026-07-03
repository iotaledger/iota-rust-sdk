// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	queryStr := `
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
	`

	query := iota_sdk.Query{
		QueryString: queryStr,
	}
	res, err := client.RunQuery(query)
	if err != nil {
		log.Fatalf("Failed to run query: %v", err)
	}
	fmt.Println(res)
}
