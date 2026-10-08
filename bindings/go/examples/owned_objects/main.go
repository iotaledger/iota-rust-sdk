// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client, err := iota_sdk.GraphQlClientNewTestnet()
	if err != nil {
		log.Fatalf("Failed to create GraphQL client: %v", err)
	}

	address := iota_sdk.AddressZero()

	objectFilter := iota_sdk.GraphQlObjectFilter{
		Owner: &address,
	}
	paginationFilter := iota_sdk.GraphQlPaginationFilter{
		Direction: iota_sdk.GraphQlDirectionForward,
	}

	objectsPage, err := client.Objects(&objectFilter, &paginationFilter)
	if err != nil {
		log.Fatalf("Failed to get owned objects: %v", err)
	}
	fmt.Printf("Owned objects (%d):\n", len(objectsPage.Data))
	for _, obj := range objectsPage.Data {
		fmt.Println(obj.Id())
	}
}
