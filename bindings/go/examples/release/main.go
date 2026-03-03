// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	chainID, err := client.ChainId()
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}
