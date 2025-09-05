// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func isNilError(err error) bool {
	if sdkErr, ok := err.(*sdk.SdkFfiError); ok {
		return sdkErr == nil
	}
	return false
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	address, err := sdk.AddressFromHex("0x0")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	objectFilter := sdk.ObjectFilter{
		Owner: &address,
	}
	paginationFilter := sdk.PaginationFilter{
		Direction: sdk.DirectionForward,
	}

	objectsPage, err := client.Objects(&paginationFilter, &objectFilter)
	if !isNilError(err) {
		log.Fatalf("Failed to get owned objects: %v", err)
	}
	fmt.Printf("Owned objects (%d):\n", len(objectsPage.Data))
	for _, obj := range objectsPage.Data {
		fmt.Println(obj.ObjectId().ToHex())
	}
}
