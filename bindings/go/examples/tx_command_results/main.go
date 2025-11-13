// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk"
)

func addrFromHex(hex string) *sdk.Address {
	address, err := sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func identifier(ident string) *sdk.Identifier {
	identifier, err := sdk.NewIdentifier(ident)
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}
	return identifier
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender := addrFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	builder := sdk.NewTransactionBuilder(sender).WithClient(client)

	packageAddr := sdk.AddressStdLib()
	moduleName := identifier("u64")
	functionName := identifier("max")
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
		[]*sdk.PtbArgument{sdk.PtbArgumentRes("res0"), sdk.PtbArgumentRes("res1")},
		// For nested results, a tuple or vec can be used to name them
		[]string{"coin0", "coin1"},
	)

	// Use named results as arguments
	builder.TransferObjects(sender, []*sdk.PtbArgument{sdk.PtbArgumentRes("coin0"), sdk.PtbArgumentRes("coin1")})

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send tx: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send tx: %v", *res.Error)
	}

	log.Print("Tx dry run was successful!")
}
