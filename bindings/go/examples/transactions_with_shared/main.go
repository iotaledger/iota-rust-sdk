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

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	sharedObjId := objIdFromHex("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")

	filter := iota_sdk.NewTransactionsFilter().WithInputObject(sharedObjId)
	transactions, err := client.Transactions(&filter, nil)
	if err != nil {
		log.Fatalf("Failed to get transactions: %v", err)
	}

	for _, transaction := range transactions.Data {
		fmt.Println("Digest:", transaction.Transaction.Digest().ToBase58())
	}
}
