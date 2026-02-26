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

	address, err := iota_sdk.AddressFromHex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f")
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
	fmt.Printf("Total Balance = %d\n", *balance)
}
