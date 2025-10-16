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

	builder := sdk.TransactionBuilderInit(sender, client)

	packageAddr := sdk.AddressStdLib()
	moduleName, _ := sdk.NewIdentifier("u64")
	functionName, _ := sdk.NewIdentifier("max")
	builder.MoveCall(
		packageAddr,
		moduleName,
		functionName,
		[]*sdk.PtbArgument{sdk.PtbArgumentU64(0), sdk.PtbArgumentU64(1000)},
		nil,
		// Assign a name to the result of this command
		[]string{"res0"},
	)

	builder.MoveCall(
		packageAddr,
		moduleName,
		functionName,
		[]*sdk.PtbArgument{sdk.PtbArgumentU64(1000), sdk.PtbArgumentU64(2000)},
		nil,
		// Assign a name to the result of this command
		[]string{"res1"},
	)

	builder.SplitCoins(
		sdk.PtbArgumentGas(),
		// Use the named results of previous commands to use as arguments
		[]*sdk.PtbArgument{sdk.PtbArgumentResultRef("res0"), sdk.PtbArgumentResultRef("res1")},
		// For nested results, a tuple or vec can be used to name them
		[]string{"coin0", "coin1"},
	)

	// Use named results as arguments
	builder.TransferObjects(sender, []*sdk.PtbArgument{sdk.PtbArgumentResultRef("coin0"), sdk.PtbArgumentResultRef("coin1")})

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	txnBase64, err := txn.ToBase64()
	if err != nil {
		log.Fatalf("Failed to serialize transaction: %v", err)
	}
	log.Printf("Signing Digest: %v", sdk.HexEncode(txn.SigningDigest()))
	log.Printf("Txn Bytes: %v", txnBase64)

	res, err := client.DryRunTx(txn, false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send tx: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send tx: %v", *res.Error)
	}

	log.Print("Tx dry run was successful!")
}
