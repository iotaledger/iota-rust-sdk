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

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	// ===========================================================================
	// Example 1: Using MoveViewCall() with typed arguments (primitives)
	// ===========================================================================
	fmt.Println("=== Example 1: MoveViewCall() with typed arguments (primitives) ===")
	fmt.Println()

	priceArgs := []*iota_sdk.MoveViewArg{
		iota_sdk.MoveViewArgU64(100),
		iota_sdk.MoveViewArgU64(25),
	}

	result, err := client.MoveViewCall(
		packageId+"::shop::discounted_price",
		nil,
		&priceArgs,
	)
	if err != nil {
		log.Fatalf("Failed to call move view function: %v", err)
	}

	if result.Error != nil {
		fmt.Println("Error:", *result.Error)
	} else if result.Results != nil {
		fmt.Println("Results:", *result.Results)
	} else {
		fmt.Println("No results")
	}

	// ===========================================================================
	// Example 2: Using MoveViewCallJson() with JSON values (primitives)
	// ===========================================================================
	fmt.Println()
	fmt.Println("=== Example 2: MoveViewCallJson() with JSON values (primitives) ===")
	fmt.Println()

	// JSON values are passed as strings; `u64` is quoted so large values
	// survive JSON.
	jsonArgs := []iota_sdk.Value{
		"\"100\"",
		"\"25\"",
	}

	result2, err := client.MoveViewCallJson(
		packageId+"::shop::discounted_price",
		nil,
		&jsonArgs,
	)
	if err != nil {
		log.Fatalf("Failed to call move view function: %v", err)
	}

	if result2.Error != nil {
		fmt.Println("JSON Error:", *result2.Error)
	} else if result2.Results != nil {
		fmt.Println("JSON Results:", *result2.Results)
	} else {
		fmt.Println("No JSON results")
	}

	// ===========================================================================
	// Example 3: Using MoveViewCall() with typed arguments (shared object)
	// ===========================================================================
	fmt.Println()
	fmt.Println("=== Example 3: MoveViewCall() with typed arguments (shared object) ===")
	fmt.Println()

	objectId, err := iota_sdk.ObjectIdFromHex(shopId)
	if err != nil {
		log.Fatalf("Failed to parse object id: %v", err)
	}

	shopArgs := []*iota_sdk.MoveViewArg{
		iota_sdk.MoveViewArgObjectId(objectId),
		iota_sdk.MoveViewArgU64(1),
	}

	shopResult, err := client.MoveViewCall(
		packageId+"::shop::sale_at",
		nil,
		&shopArgs,
	)
	if err != nil {
		log.Fatalf("Failed to call shop function: %v", err)
	}

	if shopResult.Error != nil {
		fmt.Println("Shop Error:", *shopResult.Error)
	} else if shopResult.Results != nil {
		fmt.Println("Shop Results:", *shopResult.Results)
	} else {
		fmt.Println("No shop results")
	}

	// ===========================================================================
	// Example 4: Using MoveViewCallJson() with JSON values (shared object)
	// ===========================================================================
	fmt.Println()
	fmt.Println("=== Example 4: MoveViewCallJson() with JSON values (shared object) ===")
	fmt.Println()

	shopJsonArgs := []iota_sdk.Value{
		"\"" + shopId + "\"",
		"\"1\"",
	}

	shopJsonResult, err := client.MoveViewCallJson(
		packageId+"::shop::sale_at",
		nil,
		&shopJsonArgs,
	)
	if err != nil {
		log.Fatalf("Failed to call shop function: %v", err)
	}

	if shopJsonResult.Error != nil {
		fmt.Println("Shop JSON Error:", *shopJsonResult.Error)
	} else if shopJsonResult.Results != nil {
		fmt.Println("Shop JSON Results:", *shopJsonResult.Results)
	} else {
		fmt.Println("No shop JSON results")
	}
}
