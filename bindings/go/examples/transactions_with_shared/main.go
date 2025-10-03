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

	sharedObjId, err := sdk.ObjectIdFromHex("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")
	if err != nil {
		log.Fatalf("Failed to create object ID: %v", err)
	}

	transactions, err := client.Transactions(&sdk.TransactionsFilter{InputObject: &sharedObjId}, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get transactions: %v", err)
	}

	for _, transaction := range transactions.Data {
		fmt.Println("Digest:", transaction.Transaction.AsV1().Digest().ToBase58())
	}
}
