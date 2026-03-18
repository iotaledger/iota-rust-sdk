// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	address, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to create address: %v", err)
	}

	faucetClient := iota_sdk.FaucetClientNewLocalnet()

	faucetReceipt, err := faucetClient.RequestAndWait(address)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	if err == nil {
		fmt.Println("Faucet receipt:")
		for _, coin := range faucetReceipt.Sent {
			coinIdHex := coin.Id.ToHex()
			digestBase58 := coin.TransferTxDigest.ToBase58()
			fmt.Printf("  Coin ID: %s, Amount: %d, Digest: %s\n", coinIdHex, coin.Amount, digestBase58)
		}
	} else {
		fmt.Println("Faucet receipt: nil")
	}
}
