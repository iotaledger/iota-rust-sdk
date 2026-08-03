// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	coinType := "0x2::coin::Coin<0x2::iota::IOTA>"
	coins, err := client.Objects(&iota_sdk.ObjectFilter{TypeTag: &coinType}, nil)
	if err != nil {
		log.Fatalf("Failed to get staked iota: %v", err)
	}

	if len(coins.Data) == 0 {
		fmt.Println("No IOTA coin objects found")
	} else {
		fmt.Println("IOTA coin object IDs:")
		for _, coin := range coins.Data {
			fmt.Printf("%s\n", coin.Id().ToHex())
		}
	}
}
