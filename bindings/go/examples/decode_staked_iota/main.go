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

	stakedIotaType := "0x3::staking_pool::StakedIota"
	page, err := client.Objects(&iota_sdk.ObjectFilter{TypeTag: &stakedIotaType}, nil)
	if err != nil {
		log.Fatalf("Failed to fetch StakedIota objects: %v", err)
	}

	if len(page.Data) == 0 {
		fmt.Println("No StakedIota objects on testnet right now.")
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
