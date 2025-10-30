// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func objIdFromHex(hex string) *sdk.ObjectId {
	id, err := sdk.ObjectIdFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	return id
}

func addrFromHex(hex string) *sdk.Address {
	address, err := sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender := addrFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	coinObjId := objIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")

	builder := sdk.TransactionBuilderInit(sender, client)
	builder.SplitCoins(
		sdk.PtbArgumentObjectId(coinObjId),
		[]*sdk.PtbArgument{
			sdk.PtbArgumentU64(1000),
			sdk.PtbArgumentU64(2000),
			sdk.PtbArgumentU64(3000),
		},
		[]string{"coin1", "coin2", "coin3"},
	)
	builder.TransferObjects(
		sender,
		[]*sdk.PtbArgument{sdk.PtbArgumentRes("coin1"), sdk.PtbArgumentRes("coin2"), sdk.PtbArgumentRes("coin3")},
	)
	builder.Gas(coinObjId).GasBudget(1000000000)

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to split coins: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to split coins: %v", *res.Error)
	}

	log.Print("Split coins dry run was successful!")
}
