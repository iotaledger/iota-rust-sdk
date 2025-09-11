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

	query := `
	query CustomQuery($id: UInt53) {
		epoch(id: $id) {
			epochId
			referenceGasPrice
			totalGasFees
			totalCheckpoints
			totalTransactions
		}
	}`

	variablesJson := `{"id": 1}`
	variables := string(variablesJson)

	payload1 := sdk.CustomQuery{
		Query:     query,
		Variables: &variables,
	}
	res1, err := client.RunCustomQuery(payload1)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to perform a custom query: %v", err)
	}
	fmt.Println(res1)

	payload2 := sdk.CustomQuery{
		Query:     query,
		Variables: nil,
	}
	res2, err := client.RunCustomQuery(payload2)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to perform a custom query: %v", err)
	}
	fmt.Println(res2)
}
