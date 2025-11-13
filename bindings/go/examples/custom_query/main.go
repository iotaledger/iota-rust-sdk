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

	queryEpochData := sdk.Query{
		Query: queryEpochDataStr,
	}
	res1, err := client.RunQuery(queryEpochData)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to run a query: %v", err)
	}
	fmt.Println(res1)

	variablesJson := `{"id": 1}`
	variables := string(variablesJson)

	queryEpochDataWithVariables := sdk.Query{
		Query:     queryEpochDataStr,
		Variables: &variables,
	}
	res2, err := client.RunQuery(queryEpochDataWithVariables)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to run a query with variables: %v", err)
	}
	fmt.Println(res2)

	queryChainIdStr := `
	query MyQuery {
		chainIdentifier
	}`
	queryChainId := sdk.Query{
		Query: queryChainIdStr,
	}
	res3, err := client.RunQuery(queryChainId)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to run a query: %v", err)
	}
	fmt.Println(res3)

}
