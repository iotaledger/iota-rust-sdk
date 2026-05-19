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
	if len(coins.Data) == 0 {
		log.Fatal("sender has no coins")
	}
	coinObjId := coins.Data[0].Id()

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)
	builder.SplitCoins(
		iota_sdk.PtbArgumentObjectId(coinObjId),
		[]*iota_sdk.PtbArgument{
			iota_sdk.PtbArgumentU64(1000),
			iota_sdk.PtbArgumentU64(2000),
			iota_sdk.PtbArgumentU64(3000),
		},
		[]string{"coin1", "coin2", "coin3"},
	)
	builder.TransferObjects(
		sender,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("coin1"), iota_sdk.PtbArgumentAssigned("coin2"), iota_sdk.PtbArgumentAssigned("coin3")},
	)

	res, err := builder.DryRun(false)
	if err != nil {
		log.Fatalf("Failed to split coins: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to split coins: %v", *res.Error)
	}

	log.Print("Split coins dry run was successful!")
}
