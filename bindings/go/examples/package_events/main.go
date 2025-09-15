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

	eventType := string("0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba::registry::NameRecordAddedEvent")
	eventFilter := sdk.EventFilter{
		EventType: &eventType,
	}
	limit := int32(10)
	paginationFilter := sdk.PaginationFilter{
		Direction: sdk.DirectionForward,
		Limit:     &limit,
	}

	events, err := client.Events(
		&eventFilter,
		&paginationFilter,
	)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get events: %v", err)
	}

	for _, event := range events.Data {
		fmt.Println("Type: ", event.Type)
		fmt.Println("Sender: ", event.Sender.ToHex())
		fmt.Println("Module: ", event.Module)
	}
}
