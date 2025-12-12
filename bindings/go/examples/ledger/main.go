// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	ledger, err := iota_sdk.LedgerSignerNewWithDefault("m/44'/4218'/0'/1'/0'")

	if err != nil {
		log.Fatalf("Failed to create ledger: %v", err)
	}

	address, err := ledger.GetAddress()

	if err != nil {
		log.Fatalf("Failed to get address: %v", err)
	}

	fmt.Println("Address:", address.ToHex())
	
	// client := iota_sdk.GraphQlClientNewDevnet()

	// packageAddress, err := iota_sdk.AddressFromHex("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")
	// if err != nil {
	// 	log.Fatalf("Failed to parse address: %v", err)
	// }

	// packageOpt, err := client.Package(packageAddress, nil)
	// if err.(*iota_sdk.SdkFfiError) != nil {
	// 	log.Fatalf("Failed to get package: %v", err)
	// }
	// if packageOpt == nil {
	// 	log.Fatalf("Missing package: %v", err)
	// }
	// pkg := *packageOpt

	// for moduleId := range pkg.Modules() {
	// 	moduleOpt, err := client.NormalizedMoveModule(
	// 		packageAddress,
	// 		moduleId.AsStr(),
	// 		nil,
	// 		nil,
	// 		nil,
	// 		nil,
	// 		nil,
	// 	)
	// 	if err.(*iota_sdk.SdkFfiError) != nil {
	// 		log.Fatalf("Failed to get module: %v", err)
	// 	}
	// 	if moduleOpt == nil {
	// 		log.Fatalf("Module: %v not found", moduleId.AsStr())
	// 	}
	// 	module := *moduleOpt
	// 	if module.Functions != nil {
	// 		fmt.Println("Module:", moduleId.AsStr())
	// 		for _, fun := range module.Functions.Nodes {
	// 			fmt.Println("- ", fun.String())
	// 		}
	// 		fmt.Println()
	// 	}
	// }
}
