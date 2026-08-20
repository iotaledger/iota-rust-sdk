// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func objIdFromHex(hex string) *iota_sdk.PtbArgument {
	id, err := iota_sdk.PtbArgumentObjectIdFromHex(hex)
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

	coin0 := objIdFromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")
	coin1 := objIdFromHex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")

	builder := client.TransactionBuilder(sender)
	builder.MergeCoins(coin0, []*iota_sdk.PtbArgument{coin1})

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := builder.DryRun(false)
	if err != nil {
		log.Fatalf("Failed to merge coins: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to merge coins: %v", *res.Error)
	}

	log.Print("Merge coins dry run was successful!")
}
