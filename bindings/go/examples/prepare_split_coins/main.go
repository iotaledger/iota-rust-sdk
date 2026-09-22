// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func objIdFromHex(hex string) *iota_sdk.ObjectId {
	id, err := iota_sdk.ObjectIdFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	return id
}

func addrFromHex(hex string) *iota_sdk.Address {
	address, err := iota_sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	sender := addrFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

	coinObjId := objIdFromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")

	builder := client.TransactionBuilder(sender)
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

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := builder.DryRun(false)
	if err != nil {
		log.Fatalf("Failed to split coins: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to split coins: %v", *res.Error)
	}

	log.Print("Split coins dry run was successful!")
}
