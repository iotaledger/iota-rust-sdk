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

	queryEpochDataStr := `
	query MyQuery($id: UInt53) {
		epoch(id: $id) {
			epochId
			referenceGasPrice
			totalGasFees
			totalCheckpoints
			totalTransactions
		}
	}`

	queryEpochData := iota_sdk.Query{
		QueryString: queryEpochDataStr,
	}
	res1, err := client.RunQuery(queryEpochData)
	if err != nil {
		log.Fatalf("Failed to run a query: %v", err)
	}
	fmt.Println(res1)

	variablesJson := `{"id": 1}`
	variables := string(variablesJson)

	queryEpochDataWithVariables := iota_sdk.Query{
		QueryString: queryEpochDataStr,
		Variables:   &variables,
	}
	res2, err := client.RunQuery(queryEpochDataWithVariables)
	if err != nil {
		log.Fatalf("Failed to run a query with variables: %v", err)
	}
	fmt.Println(res2)

	queryChainIdStr := `
	query MyQuery {
		chainIdentifier
	}`
	queryChainId := iota_sdk.Query{
		QueryString: queryChainIdStr,
	}
	res3, err := client.RunQuery(queryChainId)
	if err != nil {
		log.Fatalf("Failed to run a query: %v", err)
	}
	fmt.Println(res3)

}
