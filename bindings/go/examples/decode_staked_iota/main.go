// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Decode StakedIota objects into typed Go values.
//
// The GraphQL client returns each object's contents as raw BCS bytes. A single
// iota_sdk.StakedIotaTryFromObject(obj) call gives typed, named-field access to
// Id / PoolId / StakeActivationEpoch / Principal.

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	// Filtering objects by type alone scans every object on the network, which
	// the GraphQL server rejects with a timeout. Pick a recent staker and filter
	// by owner as well, so only that address' objects are looked at.
	stakeFunction := "0x3::iota_system::request_add_stake"
	limit := int32(1)
	stakers, err := client.Transactions(
		&iota_sdk.TransactionsFilter{Function: &stakeFunction},
		&iota_sdk.PaginationFilter{Direction: iota_sdk.DirectionBackward, Limit: &limit},
	)
	if err != nil {
		log.Fatalf("Failed to fetch staking transactions: %v", err)
	}

	if len(stakers.Data) == 0 {
		fmt.Println("No staking transactions on testnet right now.")
		return
	}

	staker := stakers.Data[len(stakers.Data)-1].Transaction.Sender()
	fmt.Printf("Latest staker: %s\n\n", staker.ToHex())

	stakedIotaType := "0x3::staking_pool::StakedIota"
	page, err := client.Objects(&iota_sdk.ObjectFilter{TypeTag: &stakedIotaType, Owner: &staker}, nil)
	if err != nil {
		log.Fatalf("Failed to fetch StakedIota objects: %v", err)
	}

	if len(page.Data) == 0 {
		fmt.Printf("No StakedIota objects owned by %s right now.\n", staker.ToHex())
		return
	}

	fmt.Printf("Decoded %d StakedIota object(s):\n\n", len(page.Data))
	var totalPrincipal uint64 = 0
	for _, obj := range page.Data {
		staked, err := iota_sdk.StakedIotaTryFromObject(obj)
		if err != nil {
			log.Fatalf("Failed to decode StakedIota: %v", err)
		}
		totalPrincipal += staked.Principal()
		fmt.Printf("- id:               %s\n", staked.Id().ToHex())
		fmt.Printf("  pool_id:          %s\n", staked.PoolId().ToHex())
		fmt.Printf("  stake_activation_epoch: %d\n", staked.StakeActivationEpoch())
		fmt.Printf("  principal (nanos): %d\n\n", staked.Principal())
	}

	fmt.Printf("Total principal across page: %d nanos\n", totalPrincipal)
}
