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
	client := iota_sdk.GraphQlClientNewLocalnet()

	fromAddress := addrFromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

	toAddress := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err := faucet.RequestAndWaitForFinalized(fromAddress, client)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	builder := iota_sdk.NewTransactionBuilder(fromAddress).WithClient(client)
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
