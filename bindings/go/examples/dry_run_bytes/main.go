// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	txBytesBase64 := "AAABACAAAKSYS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAEBAQABAADaGCDt9pPuMrVymQe5suyOZJgO6MAIwX6Jz7Tl7NchUQHclW3om5FOan+9g8rr78jskb4SB2Z+pVdjhjkaqCRJzPC6fSAAAAAAILFkUl8sWJyphiT+5+p5Rev6nLCp6DDtMQTNwLSMcOHw2hgg7faT7jK1cpkHubLsjmSYDujACMF+ic+05ezXIVHoAwAAAAAAAICEHgAAAAAAAA=="
	transaction, err := iota_sdk.TransactionFromBase64(txBytesBase64)
	if err != nil {
		log.Fatalf("Failed to parse transaction: %v", err)
	}

	res, err := client.DryRunTransaction(transaction, false)
	if err != nil {
		log.Fatalf("Failed to dry run transaction: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Dry run failed: %v", *res.Error)
	}

	log.Print("Dry run was successful!")
	log.Printf("Dry run result: %+v", res)
}
