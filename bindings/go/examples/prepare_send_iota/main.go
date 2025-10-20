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
	amount := sdk.PtbArgumentU64(5000000000)

	builder := sdk.TransactionBuilderInit(fromAddress, client)
	builder.SendIota(toAddress, &amount)

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send IOTA: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send IOTA: %v", *res.Error)
	}

	log.Print("Send IOTA dry run was successful!")
}
