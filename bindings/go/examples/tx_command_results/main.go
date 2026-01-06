// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func addrFromHex(hex string) *iota_sdk.Address {
	address, err := iota_sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func identifier(ident string) *iota_sdk.Identifier {
	identifier, err := iota_sdk.NewIdentifier(ident)
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}
	return identifier
}

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	sender := addrFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)

	packageAddr := iota_sdk.AddressStd()
	moduleName := identifier("u64")
	functionName := identifier("max")
	builder.MoveCall(
		packageAddr,
		moduleName,
		functionName,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentU64(0), iota_sdk.PtbArgumentU64(1000)},
		nil,
		// Assign a name to the result of this command
		[]string{"res0"},
	)

	builder.MoveCall(
		packageAddr,
		moduleName,
		functionName,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentU64(1000), iota_sdk.PtbArgumentU64(2000)},
		nil,
		// Assign a name to the result of this command
		[]string{"res1"},
	)

	builder.SplitCoins(
		iota_sdk.PtbArgumentGas(),
		// Use the named results of previous commands to use as arguments
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentRes("res0"), iota_sdk.PtbArgumentRes("res1")},
		// For nested results, a tuple or vec can be used to name them
		[]string{"coin0", "coin1"},
	)

	// Use named results as arguments
	builder.TransferObjects(sender, []*iota_sdk.PtbArgument{iota_sdk.PtbArgumentRes("coin0"), iota_sdk.PtbArgumentRes("coin1")})

	txn, err := builder.Finish()
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send tx: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send tx: %v", *res.Error)
	}

	log.Print("Tx dry run was successful!")
}
