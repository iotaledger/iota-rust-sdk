// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example demonstrates how to convert a Transaction to and from JSON.
// A similar roundtrip can be done for other types as well.

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	// A sample transaction in base64 format
	txBytesBase64 := "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA="

	// Parse the transaction from base64
	transaction, err := iota_sdk.TransactionFromBase64(txBytesBase64)
	if err != nil {
		log.Fatalf("Failed to parse transaction: %v", err)
	}

	// Convert the transaction to JSON
	json, err := transaction.ToJson()
	if err != nil {
		log.Fatalf("Failed to convert transaction to JSON: %v", err)
	}
	log.Printf("Transaction as JSON:\n%s", json)

	// Convert the JSON back to a transaction
	transactionFromJson, err := iota_sdk.TransactionFromJson(json)
	if err != nil {
		log.Fatalf("Failed to parse transaction from JSON: %v", err)
	}
	log.Printf("Parsed transaction back from JSON: %+v", transactionFromJson)
}
