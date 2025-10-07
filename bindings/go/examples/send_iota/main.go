// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender, _ := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
	recipient, _ := sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	var amount = uint64(1_000_000_000)
	builder := sdk.TransactionBuilderInit(sender, client)
	builder.SendIota(recipient, &amount)

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

	skipChecks := bool(false)
	res, err := client.DryRunTx(txn, &skipChecks)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Dry run failed: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Dry run failed: %v", *res.Error)
	}

	log.Print("Dry run successful!")
}
