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

	eventType := string("0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent")
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
		fmt.Println("Sender: ", event.Sender.ToHex())
		fmt.Println("Module: ", event.Module)
		fmt.Println("JSON: ", event.Json)
	}
}
