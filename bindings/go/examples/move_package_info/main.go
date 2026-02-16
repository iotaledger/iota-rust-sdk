// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func addressFromHex(hex string) *iota_sdk.Address {
	addr, err := iota_sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return addr
}

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	// Example package ID (replace with actual package ID)
	packageID := addressFromHex("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")

	fmt.Printf("Fetching information for package: %s\n\n", packageID.ToHex())

	// Fetch the package object
	packageOpt, err := client.Package(packageID, nil)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get package: %v", err)
	}
	if packageOpt == nil {
		log.Fatal("Package not found")
	}
	package_ := *packageOpt

	// Display package version
	fmt.Println("=== Package Version ===")
	fmt.Printf("Current version: %d\n\n", package_.Version)

	// Display modules and their functions
	fmt.Println("=== Modules ===")
	for moduleID, module := range package_.Modules {
		fmt.Printf("Module: %s\n", moduleID)

		// Fetch detailed module information
		normalizedModuleOpt, err := client.NormalizedMoveModule(
			packageID,
			moduleID,
			nil,
			iota_sdk.DefaultMoveModuleQueryOptions(),
		)
		if err.(*iota_sdk.SdkFfiError) != nil {
			log.Printf("Failed to get module %s: %v", moduleID, err)
			continue
		}

		if normalizedModuleOpt != nil {
			normalizedModule := *normalizedModuleOpt

			// Display functions
			if normalizedModule.Functions != nil {
				fmt.Println("  Functions:")
				for _, fun := range normalizedModule.Functions.Nodes {
					fmt.Printf("    - %s\n", fun.Name)
				}
			}

			// Display structs/types
			if normalizedModule.Structs != nil {
				fmt.Println("  Types:")
				for _, structDef := range normalizedModule.Structs.Nodes {
					fmt.Printf("    - %s\n", structDef.Name)

					// Try to find example objects of this type
					typeStr := fmt.Sprintf("%s::%s::%s", packageID.ToHex(), moduleID, structDef.Name)
					objectsOpt, err := client.ObjectsByType(typeStr, 3, nil)
					if err.(*iota_sdk.SdkFfiError) == nil && objectsOpt != nil {
						objects := *objectsOpt
						if len(objects) > 0 {
							fmt.Println("      Example objects:")
							for _, obj := range objects {
								fmt.Printf("        - Object ID: %s\n", obj.ObjectId().ToHex())
							}
						}
					}
				}
			}
		}
		fmt.Println()
	}

	// Display dependencies (from package's previous transaction)
	if package_.PreviousTransaction != nil {
		fmt.Println("=== Previous Transaction ===")
		fmt.Printf("Transaction digest: %s\n", package_.PreviousTransaction.ToBase58())
	}

	fmt.Println()
	fmt.Println("Package information fetched successfully!")
}
