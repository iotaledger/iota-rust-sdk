// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-sdk-go"
)

func main() {
	client, err := iota_sdk.GraphQlClientNewTestnet()
	if err != nil {
		log.Fatalf("Failed to create GraphQL client: %v", err)
	}

	chainID, err := client.ChainId()
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}
