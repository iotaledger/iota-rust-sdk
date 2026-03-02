// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func objIdFromHex(hex string) *iota_sdk.PtbArgument {
	id, err := iota_sdk.PtbArgumentObjectIdFromHex(hex)
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

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	fromAddress := addrFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

	toAddress := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	objsToTransfer := []*iota_sdk.PtbArgument{
		objIdFromHex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db"),
		objIdFromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc"),
		objIdFromHex("0x139302eb86aab7558905e4be035dcf2845cfbb2bcfb8348e81849e888ad5acf3"),
	}

	builder := iota_sdk.NewTransactionBuilder(fromAddress).WithClient(client)
	builder.TransferObjects(toAddress, objsToTransfer)

	txn, err := builder.Finish()
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to transfer objects: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to transfer objects: %v", *res.Error)
	}

	log.Print("Transfer objects dry run was successful!")
}
