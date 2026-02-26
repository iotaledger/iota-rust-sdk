// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-sdk-go"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	chainID, err := client.ChainId()
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}
