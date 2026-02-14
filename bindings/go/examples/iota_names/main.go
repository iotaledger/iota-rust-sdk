// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func failOnErr(context string, err error) {
	if err == nil {
		return
	}
	if sdkErr, ok := err.(*iota_sdk.SdkFfiError); ok {
		log.Fatalf("%s: %v", context, sdkErr)
	}
	log.Fatalf("%s: %v", context, err)
}

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	// Query with a known sample name and address used across examples.
	name := "auc.iota"
	address, err := iota_sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
	failOnErr("failed to parse address", err)

	resolvedAddressOpt, err := client.IotaNamesLookup(name)
	failOnErr("failed to lookup IOTA name", err)
	if resolvedAddressOpt == nil {
		fmt.Printf("No address found for %s\n", name)
	} else {
		fmt.Printf("Resolved %s -> %s\n", name, (*resolvedAddressOpt).ToHex())
	}

	nameFormat := iota_sdk.NameFormatDot
	defaultNameOpt, err := client.IotaNamesDefaultName(address, &nameFormat)
	failOnErr("failed to query default name", err)
	if defaultNameOpt == nil {
		fmt.Printf("No default IOTA name configured for %s\n", address.ToHex())
	} else {
		fmt.Printf("Default name for %s: %s\n", address.ToHex(), (*defaultNameOpt).String())
	}

	limit := int32(10)
	registrations, err := client.IotaNamesRegistrations(address, iota_sdk.PaginationFilter{
		Direction: iota_sdk.DirectionForward,
		Limit:     &limit,
	})
	failOnErr("failed to query name registrations", err)

	fmt.Printf("Name registrations fetched: %d\n", len(registrations.Data))
	for _, registration := range registrations.Data {
		fmt.Printf(
			"- %s (id: %s, expires_at_ms: %d)\n",
			registration.NameStr(),
			registration.Id().ToHex(),
			registration.ExpirationTimestampMs(),
		)
	}
}
