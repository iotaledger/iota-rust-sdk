// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	function := "0x3::iota_system::request_add_stake"
	transactions, err := client.Transactions(&iota_sdk.TransactionsFilter{
		Function: &function,
	}, nil)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get transactions: %v", err)
	}

	for _, transaction := range transactions.Data {
		fmt.Println("Digest:", transaction.Transaction.Digest().ToBase58())
	}
}
