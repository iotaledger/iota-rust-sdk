// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	fromAddress, err := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	toAddress, err := sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	coinObjId, err := sdk.ObjectIdFromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	coin, err := client.Object(coinObjId, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get coin: %v", err)
	}

	gasCoinObjId, err := sdk.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	gasCoin, err := client.Object(gasCoinObjId, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas coin: %v", err)
	}

	builder := sdk.NewTransactionBuilder()
	objects := []*sdk.Argument{
		builder.Input(sdk.UnresolvedInputFromObject(*coin).WithOwnedKind()),
	}
	builder.TransferObjects(objects, builder.Input(sdk.UnresolvedInputNewPure(toAddress.ToBytes())))
	builder.SetSender(fromAddress)
	builder.SetGasBudget(50000000)
	gasPrice, err := client.ReferenceGasPrice(nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	builder.SetGasPrice(*gasPrice)
	builder.AddGasObjects([]*sdk.UnresolvedInput{sdk.UnresolvedInputFromObject(*gasCoin).WithOwnedKind()})

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	txnBytes, err := txn.BcsSerialize()
	if err != nil {
		log.Fatalf("Failed to serialize transaction: %v", err)
	}
	log.Printf("Signing Digest: %v", sdk.HexEncode(txn.SigningDigest()))
	log.Printf("Txn Bytes: %v", sdk.Base64Encode(txnBytes))

	res, err := client.DryRunTx(txn, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send IOTA: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send IOTA: %v", *res.Error)
	}

	log.Print("Send IOTA dry run was successful!")
}
