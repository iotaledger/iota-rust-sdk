// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	// Query events emitted by the validator-set module in the IOTA system
	// framework (0x3). These fire on every epoch change so they are reliably
	// present on every network including localnet.
	eventType := string("0x3::validator::StakingRequestEvent")
	eventFilter := iota_sdk.EventFilter{
		EventType: &eventType,
	}
	limit := int32(10)
	paginationFilter := iota_sdk.PaginationFilter{
		Direction: iota_sdk.DirectionForward,
		Limit:     &limit,
	}

	events, err := client.Events(
		&eventFilter,
		&paginationFilter,
	)
	if err != nil {
		log.Fatalf("Failed to get events: %v", err)
	}

	for _, event := range events.Data {
		fmt.Println("Type: ", event.Type)
		if event.Sender != nil {
			fmt.Println("Sender: ", (*event.Sender).ToHex())
		}
		if event.Module != nil {
			fmt.Println("Module: ", *event.Module)
		}
		fmt.Println("JSON: ", event.Json)
	}
}
