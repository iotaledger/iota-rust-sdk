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
	client := iota_sdk.GraphQlClientNewTestnet()

	sender := addrFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

	builder := client.TransactionBuilder(sender)

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
		// Use the assigned results of previous commands to use as arguments
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("res0"), iota_sdk.PtbArgumentAssigned("res1")},
		// For nested results, a tuple or vec can be used to assign them
		[]string{"coin0", "coin1"},
	)

	// Use assigned results as arguments
	builder.TransferObjects(sender, []*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("coin0"), iota_sdk.PtbArgumentAssigned("coin1")})

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err != nil {
		log.Fatalf("Failed to send tx: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send tx: %v", *res.Error)
	}

	log.Print("Tx dry run was successful!")
}
