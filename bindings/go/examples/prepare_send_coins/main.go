// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk"
)

func objIdFromHex(hex string) *sdk.PtbArgument {
	id, err := sdk.PtbArgumentObjectIdFromHex(hex)
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

	fromAddress := addrFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
	toAddress := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	// This is a coin of type
	// 0x3358bea865960fea2a1c6844b6fc365f662463dd1821f619838eb2e606a53b6a::cert::CERT
	coinObjId := objIdFromHex("0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9")
	amount := sdk.PtbArgumentU64(50000000000)

	builder := sdk.NewTransactionBuilder(fromAddress).WithClient(client)
	builder.SendCoins([]*sdk.PtbArgument{coinObjId}, toAddress, &amount)

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send coins: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send coins: %v", *res.Error)
	}

	log.Print("Send coins dry run was successful!")
}
