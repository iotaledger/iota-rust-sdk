// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client, err := iota_sdk.GrpcClientNewTestnet()
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	owner, err := iota_sdk.AddressFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	// First page: 10 results, no filter on type. The returned page includes a
	// `NextPageToken` to feed back in for the following page.
	pageSize := uint32(10)
	page, err := client.OwnedObjects(owner, nil, &pageSize, nil)
	if err != nil {
		log.Fatalf("Failed to get owned objects: %v", err)
	}
	fmt.Printf("First page: %d objects\n", len(page.Objects))
	for _, obj := range page.Objects {
		fmt.Println(" ", obj.Id().ToHex())
	}
	if page.NextPageToken != nil {
		fmt.Println("  ...more pages available")
	}

	// Auto-paginate: only IOTA coins, capped at 50 across all pages.
	limit := uint32(50)
	gasCoin := iota_sdk.StructTagNewGasCoin()
	coins, err := client.AllOwnedObjects(owner, &gasCoin, &limit)
	if err != nil {
		log.Fatalf("Failed to get coin objects: %v", err)
	}
	fmt.Println("---")
	fmt.Printf("Up to 50 IOTA coin objects (%d returned):\n", len(coins))
	for _, obj := range coins {
		fmt.Println(" ", obj.Id().ToHex())
	}
}
