// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	queryEpochDataStr := `
	query CustomQuery($id: UInt53) {
		epoch(id: $id) {
			epochId
			referenceGasPrice
			totalGasFees
			totalCheckpoints
			totalTransactions
		}
	}`

	queryEpochData := sdk.CustomQuery{
		Query:     queryEpochDataStr,
		Variables: nil,
	}
	res1, err := client.RunCustomQuery(queryEpochData)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to run a custom query: %v", err)
	}
	fmt.Println(res1)

	variablesJson := `{"id": 1}`
	variables := string(variablesJson)
	queryEpochDataWithVariables := sdk.CustomQuery{
		Query:     queryEpochDataStr,
		Variables: &variables,
	}
	res2, err := client.RunCustomQuery(queryEpochDataWithVariables)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to run a custom query with variables: %v", err)
	}
	fmt.Println(res2)

	queryChainIdentifierStr := `
	query CustomQuery {
		chainIdentifier
	}`
	queryChainIdentifier := sdk.CustomQuery{
		Query:     queryChainIdentifierStr,
		Variables: nil,
	}
	res3, err := client.RunCustomQuery(queryChainIdentifier)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to run a custom query: %v", err)
	}
	fmt.Println(res3)

}
