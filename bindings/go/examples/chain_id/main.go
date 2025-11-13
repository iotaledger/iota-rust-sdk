// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	chainID, err := client.ChainId()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}
