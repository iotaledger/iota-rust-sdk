// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
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

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	sender := addrFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

	coinId := objIdFromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")

	recipients := []struct {
		address string
		amount  uint64
	}{
		{"0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11", 1_000_000_000},
		{"0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522", 2_000_000_000},
	}

	builder := client.TransactionBuilder(sender)

	// Prepare amounts and labels
	var amounts []*iota_sdk.PtbArgument
	var labels []string
	for idx, r := range recipients {
		labels = append(labels, fmt.Sprintf("coin%v", idx))
		amounts = append(amounts, iota_sdk.PtbArgumentU64(r.amount))
	}

	// Split a coin into multiple coins
	builder.SplitCoins(iota_sdk.PtbArgumentObjectId(coinId), amounts, labels)

	for idx, r := range recipients {
		recipient := addrFromHex(r.address)
		builder.TransferObjects(recipient, []*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned(labels[idx])})
	}

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTransaction(txn, false)
	if err != nil {
		log.Fatalf("Failed to dry run send IOTA: %v", err)
	}
	if res.Error != nil {
		log.Fatalf("Failed to send IOTA: %v", *res.Error)
	}
	log.Print("Send IOTA dry run was successful!")
}
