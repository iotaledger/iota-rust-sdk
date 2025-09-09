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

	objectsPage, err := client.Objects(&objectFilter, &paginationFilter)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get owned objects: %v", err)
	}
	fmt.Printf("Owned objects (%d):\n", len(objectsPage.Data))
	for _, obj := range objectsPage.Data {
		fmt.Println(obj.ObjectId().ToHex())
	}
}
