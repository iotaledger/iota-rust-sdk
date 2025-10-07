// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender, _ := sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	sponsor, _ := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	builder := sdk.TransactionBuilderInit(sender, client)

	packageAddr, _ := sdk.AddressFromHex("0x1")
	moduleName, _ := sdk.NewIdentifier("u8")
	functionName, _ := sdk.NewIdentifier("max")

	builder.MoveCall(
		packageAddr,
		moduleName,
		functionName,
		[]*sdk.PtbArgument{sdk.PtbArgumentU8(0), sdk.PtbArgumentU8(1)},
		nil,
		nil,
	)

	gasObjId, _ := sdk.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")
	builder.Gas(gasObjId).Sponsor(sponsor)

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	txnBytes, err := txn.AsV1().BcsSerialize()
	if err != nil {
		log.Fatalf("Failed to serialize transaction: %v", err)
	}
	log.Printf("Signing Digest: %v", sdk.HexEncode(txn.AsV1().SigningDigest()))
	log.Printf("Txn Bytes: %v", sdk.Base64Encode(txnBytes))

	skipChecks := bool(false)
	res, err := client.DryRunTx(txn, &skipChecks)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send gas sponsor tx: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send gas sponsor tx: %v", *res.Error)
	}

	log.Print("Gas sponsor tx dry run was successful!")
}
