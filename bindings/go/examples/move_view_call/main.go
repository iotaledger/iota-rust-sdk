// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	// ===========================================================================
	// Example 1: Using MoveViewCall() with typed arguments (blake2b256)
	// ===========================================================================
	fmt.Println("=== Example 1: MoveViewCall() with typed arguments (blake2b256) ===")
	fmt.Println()

	// Using typed arguments: an array of u8 values using the u8_vec constructor
	hashArgs := []*iota_sdk.MoveViewArg{
		iota_sdk.MoveViewArgU8Vec([]uint8{0, 1, 2}),
	}

	result, err := client.MoveViewCall(
		"0x2::hash::blake2b256",
		nil,
		&hashArgs,
	)
	if err != nil {
		if sdkErr, ok := err.(*iota_sdk.SdkFfiError); !ok || sdkErr != nil {
			log.Fatalf("Failed to call move view function: %v", err)
		}
	}

	if result.Error != nil {
		fmt.Println("Error:", *result.Error)
	} else if result.Results != nil {
		fmt.Println("Results:", *result.Results)
	} else {
		fmt.Println("No results")
	}

	// ===========================================================================
	// Example 2: Using MoveViewCallJson() with JSON values (blake2b256)
	// ===========================================================================
	fmt.Println()
	fmt.Println("=== Example 2: MoveViewCallJson() with JSON values (blake2b256) ===")
	fmt.Println()

	// JSON values are passed as strings
	jsonArgs := []iota_sdk.Value{
		"[0,1,2]",
	}

	result2, err := client.MoveViewCallJson(
		"0x2::hash::blake2b256",
		nil,
		&jsonArgs,
	)
	if err != nil {
		if sdkErr, ok := err.(*iota_sdk.SdkFfiError); !ok || sdkErr != nil {
			log.Fatalf("Failed to call move view function: %v", err)
		}
	}

	if result2.Error != nil {
		fmt.Println("JSON Error:", *result2.Error)
	} else if result2.Results != nil {
		fmt.Println("JSON Results:", *result2.Results)
	} else {
		fmt.Println("No JSON results")
	}

	// ===========================================================================
	// Example 3: Using MoveViewCall() with typed arguments (auction)
	// ===========================================================================
	fmt.Println()
	fmt.Println("=== Example 3: MoveViewCall() with typed arguments (auction) ===")
	fmt.Println()

	objectId, err := iota_sdk.ObjectIdFromHex("0x2292ea885039babe8c320f19e0b7546ebdef2b2f6cf2be600bf994cdb51e0050")
	if err != nil {
		log.Fatalf("Failed to parse object id: %v", err)
	}

	auctionArgs := []*iota_sdk.MoveViewArg{
		iota_sdk.MoveViewArgObjectId(objectId),
		iota_sdk.MoveViewArgString("auc.iota"),
	}

	auctionResult, err := client.MoveViewCall(
		"0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d::auction::get_auction_metadata",
		nil,
		&auctionArgs,
	)
	if err != nil {
		if sdkErr, ok := err.(*iota_sdk.SdkFfiError); !ok || sdkErr != nil {
			log.Fatalf("Failed to call auction function: %v", err)
		}
	}

	if auctionResult.Error != nil {
		fmt.Println("Auction Error:", *auctionResult.Error)
	} else if auctionResult.Results != nil {
		fmt.Println("Auction Results:", *auctionResult.Results)
	} else {
		fmt.Println("No auction results")
	}

	// ===========================================================================
	// Example 4: Using MoveViewCallJson() with JSON values (auction)
	// ===========================================================================
	fmt.Println()
	fmt.Println("=== Example 4: MoveViewCallJson() with JSON values (auction) ===")
	fmt.Println()

	// JSON values are passed as strings (object IDs and strings are valid JSON)
	auctionJsonArgs := []iota_sdk.Value{
		"\"0x2292ea885039babe8c320f19e0b7546ebdef2b2f6cf2be600bf994cdb51e0050\"",
		"\"auc.iota\"",
	}

	auctionJsonResult, err := client.MoveViewCallJson(
		"0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d::auction::get_auction_metadata",
		nil,
		&auctionJsonArgs,
	)
	if err != nil {
		if sdkErr, ok := err.(*iota_sdk.SdkFfiError); !ok || sdkErr != nil {
			log.Fatalf("Failed to call auction function: %v", err)
		}
	}

	if auctionJsonResult.Error != nil {
		fmt.Println("Auction JSON Error:", *auctionJsonResult.Error)
	} else if auctionJsonResult.Results != nil {
		fmt.Println("Auction JSON Results:", *auctionJsonResult.Results)
	} else {
		fmt.Println("No auction JSON results")
	}
}
