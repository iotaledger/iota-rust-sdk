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

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	fromAddress := addrFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

	toAddress := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	builder := client.TransactionBuilder(fromAddress)
	builder.SendIota(toAddress, iota_sdk.PtbArgumentU64(5000000000))

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err != nil {
		log.Fatalf("Failed to send IOTA: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to send IOTA: %v", *res.Error)
	}

	log.Print("Send IOTA dry run was successful!")
}
