// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func identifier(ident string) *iota_sdk.Identifier {
	identifier, err := iota_sdk.NewIdentifier(ident)
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}
	return identifier
}

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	sender := iota_sdk.AddressZero()
	stdAddress := iota_sdk.AddressStd()

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)

	u64Module := identifier("u64")
	maxFn := identifier("max")
	minFn := identifier("min")

	// Build a small chain of stdlib Move calls and extract the return value
	// from the final command via dry_run.
	builder.MoveCall(
		stdAddress,
		u64Module,
		maxFn,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentU64(100), iota_sdk.PtbArgumentU64(200)},
		nil,
		[]string{"max_value"},
	)

	builder.MoveCall(
		stdAddress,
		u64Module,
		minFn,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("max_value"), iota_sdk.PtbArgumentU64(150)},
		nil,
		[]string{"result"},
	)

	res, err := builder.DryRun(true)
	if err != nil {
		log.Fatalf("Failed to dry run transaction: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to dry-run: %v", *res.Error)
	}

	if len(res.Results) > 0 {
		lastEffect := res.Results[len(res.Results)-1]
		if len(lastEffect.ReturnValues) > 0 {
			returnValue := lastEffect.ReturnValues[0]
			if returnValue.TypeTag.IsU64() && len(returnValue.Bcs) == 8 {
				value := binary.LittleEndian.Uint64(returnValue.Bcs)
				fmt.Printf("min(max(100, 200), 150) = %d\n", value)
			} else {
				fmt.Println("Failed to extract u64 from results")
			}
		} else {
			fmt.Println("No return value in last effect")
		}
	} else {
		fmt.Println("No results found")
	}
}
