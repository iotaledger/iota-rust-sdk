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

	transactions, err := client.Transactions(nil, nil)
	if err != nil {
		log.Fatalf("Failed to fetch transactions: %v", err)
	}
	if len(transactions.Data) == 0 {
		log.Fatal("No transactions found")
	}
	digest := transactions.Data[0].Transaction.Digest()

	signed_transaction, err := client.Transaction(digest)
	if err != nil {
		log.Fatalf("Failed to get transaction: %v", err)
	}
	fmt.Printf("Signed Transaction: %v\n", signed_transaction)

	transaction_effects, err := client.TransactionEffects(digest)
	if err != nil {
		log.Fatalf("Failed to get transaction effects: %v", err)
	}
	fmt.Printf("Transaction Effects: %v\n", transaction_effects)

	transaction_data_effects, err := client.TransactionDataEffects(digest)
	if err != nil {
		log.Fatalf("Failed to get transaction data effects: %v", err)
	}
	fmt.Printf("Transaction Data Effects: %v\n", transaction_data_effects)
}
