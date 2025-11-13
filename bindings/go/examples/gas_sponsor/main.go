// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk"
)

func objIdFromHex(hex string) *sdk.ObjectId {
	id, err := sdk.ObjectIdFromHex(hex)
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

func identifier(ident string) *sdk.Identifier {
	identifier, err := sdk.NewIdentifier(ident)
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}
	return identifier
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	sponsor := addrFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	builder := sdk.NewTransactionBuilder(sender).WithClient(client)

	packageAddr := sdk.AddressStdLib()
	moduleName := identifier("u8")
	functionName := identifier("max")

	builder.MoveCall(
		packageAddr,
		moduleName,
		functionName,
		[]*sdk.PtbArgument{sdk.PtbArgumentU8(0), sdk.PtbArgumentU8(1)},
		nil,
		nil,
	)

	builder.Sponsor(sponsor)

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to send gas sponsor tx: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send gas sponsor tx: %v", *res.Error)
	}

	log.Print("Gas sponsor tx dry run was successful!")
}
