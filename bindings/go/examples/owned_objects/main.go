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

	address := iota_sdk.AddressZero()

	objectFilter := iota_sdk.ObjectFilter{
		Owner: &address,
	}
	paginationFilter := iota_sdk.PaginationFilter{
		Direction: iota_sdk.DirectionForward,
	}

	objectsPage, err := client.Objects(&objectFilter, &paginationFilter)
	if err != nil {
		log.Fatalf("Failed to get owned objects: %v", err)
	}
	fmt.Printf("Owned objects (%d):\n", len(objectsPage.Data))
	for _, obj := range objectsPage.Data {
		fmt.Println(obj.Id().ToHex())
	}
}
