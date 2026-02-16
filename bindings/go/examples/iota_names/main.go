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
	_ = iota_sdk.GraphQlClientNewDevnet()

	fmt.Println("=== IOTA Names Example ===")
	fmt.Println()
	fmt.Println("1. Resolving name 'name.iota'")
	fmt.Println("   (Implementation would use TransactionBuilder)")
	fmt.Println()
	fmt.Println("2. Checking availability of 'test123.iota'")
	fmt.Println("   (Implementation would use TransactionBuilder)")
}
