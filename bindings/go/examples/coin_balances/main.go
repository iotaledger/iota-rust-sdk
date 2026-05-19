// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	address, err := iota_sdk.AddressFromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWaitForFinalized(address, client)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
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
