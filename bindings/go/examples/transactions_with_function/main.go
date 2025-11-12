// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	function := "0x3::iota_system::request_add_stake"
	transactions, err := client.Transactions(&sdk.TransactionsFilter{
		Function: &function,
	}, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get transactions: %v", err)
	}

	for _, transaction := range transactions.Data {
		fmt.Println("Digest:", transaction.Transaction.Digest().ToBase58())
	}
}
