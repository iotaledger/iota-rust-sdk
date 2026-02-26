// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	chainID, err := client.ChainId()
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}
