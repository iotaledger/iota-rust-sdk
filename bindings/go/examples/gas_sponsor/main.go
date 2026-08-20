// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func objIdFromHex(hex string) *iota_sdk.ObjectId {
	id, err := iota_sdk.ObjectIdFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	return id
}

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

	sender := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	sponsor := addrFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

	builder := client.TransactionBuilder(sender)

	packageAddr := iota_sdk.AddressStd()
	moduleName := identifier("u8")
	functionName := identifier("max")

	builder.MoveCall(
		packageAddr,
		moduleName,
		functionName,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentU8(0), iota_sdk.PtbArgumentU8(1)},
		nil,
		nil,
	)

	builder.Sponsor(sponsor)

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err != nil {
		log.Fatalf("Failed to send gas sponsor tx: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send gas sponsor tx: %v", *res.Error)
	}

	log.Print("Gas sponsor tx dry run was successful!")
}
