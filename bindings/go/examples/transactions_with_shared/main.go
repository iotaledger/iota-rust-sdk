// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	// The IOTA system state object (0x5) is a well-known shared object that is
	// present on every network including localnet.
	sharedObjId := iota_sdk.ObjectIdSystemState()

	transactions, err := client.Transactions(&iota_sdk.TransactionsFilter{InputObject: &sharedObjId}, nil)
	if err != nil {
		log.Fatalf("Failed to get transactions: %v", err)
	}

	for _, transaction := range transactions.Data {
		fmt.Println("Digest:", transaction.Transaction.Digest().ToBase58())
	}
}
