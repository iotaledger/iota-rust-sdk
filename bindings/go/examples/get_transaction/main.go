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
	digest, err := iota_sdk.TransactionDigestFromBase58("3wN9oLKfvCjCd7uFW1D6fp1uSEsD3wJ2cU61YULNKzFh")
	if err != nil {
		log.Fatalf("Failed to parse digest: %v", err)
	}

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
