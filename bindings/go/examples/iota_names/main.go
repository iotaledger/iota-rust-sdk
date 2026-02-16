// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

const (
	IotaNamesPackage  = "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba"
	IotaNamesRegistry = "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	fmt.Println("=== IOTA Names Example ===\n")

	// Example 1: Lookup and resolve a name
	name := "name.iota"
	fmt.Printf("1. Resolving name '%s'\n", name)
	address := resolveName(client, name)
	if address != nil {
		fmt.Printf("   Resolved to: %s\n\n", address.ToHex())
	} else {
		fmt.Println("   Name not found or has no target address\n")
	}

	// Example 2: Check name availability
	testName := "test123.iota"
	fmt.Printf("2. Checking availability of '%s'\n", testName)
	isAvailable := checkAvailability(client, testName)
	if isAvailable {
		fmt.Println("   Name is available!\n")
	} else {
		fmt.Println("   Name is already registered\n")
	}
}

func resolveName(client *iota_sdk.GraphQlClient, name string) *iota_sdk.Address {
	// Simplified example - placeholder implementation
	fmt.Printf("   Attempting to resolve: %s\n", name)
	// In production, use TransactionBuilder with move calls
	return nil
}

func checkAvailability(client *iota_sdk.GraphQlClient, name string) bool {
	// Simplified example - placeholder implementation
	fmt.Printf("   Checking availability for: %s\n", name)
	return true
}
