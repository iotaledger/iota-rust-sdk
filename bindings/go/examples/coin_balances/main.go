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

	address, err := iota_sdk.AddressFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	coins, err := client.Coins(address, nil, nil)
	if err != nil {
		log.Fatalf("Failed to get coins: %v", err)
	}

	for _, coin := range coins.Data {
		fmt.Printf("Coin = %s, Coin Type = %s, Balance = %d\n", coin.Id().ToHex(), coin.CoinType().AsStructTag(), coin.Balance())
	}

	balance, err := client.Balance(address, nil)
	if err != nil {
		log.Fatalf("Failed to get balance: %v", err)
	}
	var totalBalance uint64
	if balance != nil {
		totalBalance = *balance
	}
	fmt.Printf("Total Balance = %d\n", totalBalance)
}
