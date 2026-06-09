// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Fetch all transactions for an address (outgoing and incoming).
//
// The GraphQL service does not have a single filter that returns transactions
// in both directions for an address. To get the full history, run two queries
// and merge the results.
package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	address, err := iota_sdk.AddressFromHex("0xa7c2cf9d8f8d95ff69d7a598c49c77acc36253f496f064a533ad306879b40bfa")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	outgoing, err := client.Transactions(&iota_sdk.TransactionsFilter{
		SentAddress: &address,
	}, nil)
	if err != nil {
		log.Fatalf("Failed to fetch outgoing transactions: %v", err)
	}

	incoming, err := client.Transactions(&iota_sdk.TransactionsFilter{
		RecvAddress: &address,
	}, nil)
	if err != nil {
		log.Fatalf("Failed to fetch incoming transactions: %v", err)
	}

	fmt.Printf("Transactions for %s\n", address.ToHex())

	fmt.Printf("\nOutgoing (sent by address): %d\n", len(outgoing.Data))
	for _, tx := range outgoing.Data {
		fmt.Printf("  - %s\n", tx.Transaction.Digest().ToBase58())
	}

	fmt.Printf("\nIncoming (received by address): %d\n", len(incoming.Data))
	for _, tx := range incoming.Data {
		fmt.Printf("  - %s\n", tx.Transaction.Digest().ToBase58())
	}
}
