// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

// The `view_demo` package published on testnet.
const packageId = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4"

// A shared `view_demo::shop::Shop` created when the package was published.
const shopId = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20"

func describe(outputs iota_sdk.ViewFunctionCallOutputs) string {
	if outputs.ReturnValues != nil {
		values := []iota_sdk.Value{}
		for _, value := range *outputs.ReturnValues {
			if value.Json != nil {
				values = append(values, *value.Json)
			}
		}
		return fmt.Sprintf("returned %v", values)
	}
	source := ""
	if outputs.ExecutionError != nil && outputs.ExecutionError.Source != nil {
		source = *outputs.ExecutionError.Source
	}
	return fmt.Sprintf("aborted (%s)", source)
}

func main() {
	client, err := iota_sdk.GrpcClientNewTestnet()
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	// A single call. `discounted_price` is declared `#[view]` in the package.
	priceArgs := []*iota_sdk.MoveViewArg{
		iota_sdk.MoveViewArgU64(100),
		iota_sdk.MoveViewArgU64(25),
	}
	outputs, err := client.ViewFunctionCall(packageId+"::shop::discounted_price", nil, &priceArgs, nil)
	if err != nil {
		log.Fatalf("Failed to call view function: %v", err)
	}
	fmt.Println("discounted_price:", describe(outputs))

	// Three calls in one request: the call from above, the same function with
	// a discount over 100% so that it aborts, and a function that is not
	// declared `#[view]`. Each call runs on its own, so the rejected one does
	// not affect the others.
	shop, err := iota_sdk.ObjectIdFromHex(shopId)
	if err != nil {
		log.Fatalf("Failed to parse object id: %v", err)
	}
	results, err := client.ViewFunctionCalls([]iota_sdk.ViewFunctionCallInput{
		{
			FqFunctionName: packageId + "::shop::discounted_price",
			CallArgs:       []*iota_sdk.MoveViewArg{iota_sdk.MoveViewArgU64(100), iota_sdk.MoveViewArgU64(25)},
		},
		{
			FqFunctionName: packageId + "::shop::discounted_price",
			CallArgs:       []*iota_sdk.MoveViewArg{iota_sdk.MoveViewArgU64(100), iota_sdk.MoveViewArgU64(200)},
		},
		{
			FqFunctionName: packageId + "::shop::record_sale",
			CallArgs:       []*iota_sdk.MoveViewArg{iota_sdk.MoveViewArgObjectId(shop), iota_sdk.MoveViewArgU64(5)},
		},
	}, nil)
	if err != nil {
		log.Fatalf("Failed to call view functions: %v", err)
	}

	names := []string{"priced", "over-discounted", "record_sale"}
	for i, result := range results {
		if result.Outputs != nil {
			fmt.Printf("%s: %s\n", names[i], describe(*result.Outputs))
		} else {
			fmt.Printf("%s: rejected by the node (%s)\n", names[i], *result.Error)
		}
	}
}
