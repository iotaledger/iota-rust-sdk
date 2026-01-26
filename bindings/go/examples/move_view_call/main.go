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
	// Example 1: Using MoveViewCall() for blake2b256 hash function
	// ===========================================================================
	fmt.Println("=== Example 1: MoveViewCall() for blake2b256 ===")
	fmt.Println()

	hashArgs := []string{
		"[0,1,2]",
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
	// Example 2: Using MoveViewCall() for auction metadata
	// ===========================================================================
	fmt.Println()
	fmt.Println("=== Example 2: MoveViewCall() for auction ===")
	fmt.Println()

	auctionArgs := []string{
		"0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b",
		"auc.iota",
	}

	auctionResult, err := client.MoveViewCall(
		"0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
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
}
