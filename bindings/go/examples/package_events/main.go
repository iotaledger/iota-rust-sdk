// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	eventType := string("0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba::registry::NameRecordAddedEvent")
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
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get events: %v", err)
	}

	for _, event := range events.Data {
		fmt.Println("Type: ", event.Type)
		fmt.Println("Sender: ", event.Sender.ToHex())
		fmt.Println("Module: ", event.Module)
		fmt.Println("JSON: ", event.Json)
	}
}
