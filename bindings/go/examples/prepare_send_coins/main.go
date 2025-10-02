// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	fromAddress, _ := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	toAddress, _ := sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	// This is a coin of type
	// 0x3358bea865960fea2a1c6844b6fc365f662463dd1821f619838eb2e606a53b6a::cert::CERT
	coinObjId, _ := sdk.ObjectIdFromHex("0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9")
	amount := uint64(50000000000)

	gasCoinObjId, _ := sdk.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")

	builder := sdk.TransactionBuilderInit(fromAddress, client)
	builder.SendCoins([]*sdk.ObjectId{coinObjId}, toAddress, &amount)
	builder.Gas(gasCoinObjId).GasBudget(1000000000)

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	txnBytes, err := txn.BcsSerialize()
	if err != nil {
		log.Fatalf("Failed to serialize transaction: %v", err)
	}
	log.Printf("Signing Digest: %v", sdk.HexEncode(txn.SigningDigest()))
	log.Printf("Txn Bytes: %v", sdk.Base64Encode(txnBytes))

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send coins: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send coins: %v", *res.Error)
	}

	log.Print("Send coins dry run was successful!")
}
