// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender, _ := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	coinId, _ := sdk.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")

	recipients := []struct {
		address string
		amount  uint64
	}{
		{"0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11", 1_000_000_000},
		{"0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522", 2_000_000_000},
	}

	builder := sdk.TransactionBuilderInit(sender, client)

	// Prepare amounts and labels
	var amounts []*sdk.PtbArgument
	var labels []string
	for idx, r := range recipients {
		labels = append(labels, fmt.Sprintf("coin%v", idx))
		amounts = append(amounts, sdk.PtbArgumentU64(r.amount))
	}

	// Split a coin into multiple coins
	builder.SplitCoins(sdk.PtbArgumentObjectId(coinId), amounts, labels)

	for idx, r := range recipients {
		recipient, _ := sdk.AddressFromHex(r.address)
		builder.TransferObjects(recipient, []*sdk.PtbArgument{sdk.PtbArgumentRes(labels[idx])})
	}

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	txnBytes, err := txn.ToBytes()
	if err != nil {
		log.Fatalf("Failed to serialize transaction: %v", err)
	}
	log.Printf("Signing Digest: %v", sdk.HexEncode(txn.SigningDigest()))
	log.Printf("Txn Bytes: %v", sdk.Base64Encode(txnBytes))

	res, err := client.DryRunTx(txn, false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to dry run send IOTA: %v", err)
	}
	if res.Error != nil {
		log.Fatalf("Failed to send IOTA: %v", *res.Error)
	}
	log.Print("Send IOTA dry run was successful!")
}
