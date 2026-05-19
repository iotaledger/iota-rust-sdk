// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func addrFromHex(hex string) *iota_sdk.Address {
	address, err := iota_sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	sender := addrFromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err := faucet.RequestAndWaitForFinalized(sender, client)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	coins, err := client.Coins(sender, nil, nil)
	if err != nil {
		log.Fatalf("Failed to fetch coins: %v", err)
	}
	if len(coins.Data) < 2 {
		log.Fatal("sender has only one coin, need two to merge")
	}
	coin0 := iota_sdk.PtbArgumentObjectId(coins.Data[0].Id())
	coin1 := iota_sdk.PtbArgumentObjectId(coins.Data[1].Id())

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)
	builder.MergeCoins(coin0, []*iota_sdk.PtbArgument{coin1})

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err != nil {
		log.Fatalf("Failed to merge coins: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to merge coins: %v", *res.Error)
	}

	log.Print("Merge coins dry run was successful!")
}
