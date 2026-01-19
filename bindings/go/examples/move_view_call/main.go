// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
	client := iota_sdk.GraphQlClientNewDevnet()

	arguments := []string{
		"0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b",
		"auc.iota",
	}

	result, err := client.MoveViewCall(
		"0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
		nil,
		&arguments,
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

	hashArgs := []string{
		"[0,1,2]",
	}

	hashResult, err := client.MoveViewCall(
		"0x2::hash::blake2b256",
		nil,
		&hashArgs,
	)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to call hash function: %v", err)
	}

	if hashResult.Error != nil {
		fmt.Println("Hash Error:", *hashResult.Error)
	} else if hashResult.Results != nil {
		fmt.Println("Hash Results:", *hashResult.Results)
	} else {
		fmt.Println("No hash results")
	}

	// Using TransactionBuilder for move view call
	fmt.Println("Using TransactionBuilder for move view call:")
	sender := iota_sdk.AddressZero()
	txBuilder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)

	objId, err := iota_sdk.PtbArgumentObjectIdFromHex("0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b")
	if err != nil {
		log.Fatalf("Failed to create object ID: %v", err)
	}

	ptbArg := iota_sdk.PtbArgumentString("\"auc.iota\"")

	packageAddress, err := iota_sdk.AddressFromHex("0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50")
	if err != nil {
		log.Fatalf("Failed to parse package address: %v", err)
	}
	module_name := identifier("auction")
	function_name := identifier("get_auction_metadata")

	txBuilder.MoveCall(
		packageAddress,
		module_name,
		function_name,
		[]*iota_sdk.PtbArgument{objId, ptbArg},
		nil,
		nil,
	)

	txResult, err := txBuilder.MoveViewCall()
	if err != nil {
		if sdkErr, ok := err.(*iota_sdk.SdkFfiError); !ok || sdkErr != nil {
			log.Fatalf("Failed to call move view function with tx builder: %v", err)
		}
	}

	if txResult.Error != nil {
		fmt.Println("Tx Builder Error:", *txResult.Error)
	} else if txResult.Results != nil {
		fmt.Println("Tx Builder Results:", *txResult.Results)
	} else {
		fmt.Println("No tx builder results")
	}

}
