// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	name := "name.iota"
	fmt.Printf("Resolving name: %s\n", name)

	resolvedAddressOpt, err := client.IotaNamesLookup(name)
	if err != nil {
		log.Fatalf("Failed to lookup name: %v", err)
	}
	if resolvedAddressOpt == nil {
		fmt.Printf("No address resolved for %s\n", name)
		return
	}
	resolvedAddress := *resolvedAddressOpt
	fmt.Printf("Resolved address: %s\n", resolvedAddress.ToHex())

	dotFormat := iota_sdk.NameFormatDot
	defaultNameDotOpt, err := client.IotaNamesDefaultName(resolvedAddress, &dotFormat)
	if err != nil {
		log.Fatalf("Failed to fetch default dot-format name: %v", err)
	}
	if defaultNameDotOpt == nil {
		fmt.Println("No default dot-format name found")
	} else {
		defaultNameDot := *defaultNameDotOpt
		fmt.Printf("Default name (dot): %s\n", defaultNameDot.String())
	}

	atFormat := iota_sdk.NameFormatAt
	defaultNameAtOpt, err := client.IotaNamesDefaultName(resolvedAddress, &atFormat)
	if err != nil {
		log.Fatalf("Failed to fetch default at-format name: %v", err)
	}
	if defaultNameAtOpt == nil {
		fmt.Println("No default at-format name found")
	} else {
		defaultNameAt := *defaultNameAtOpt
		fmt.Printf("Default name (at): %s\n", defaultNameAt.Format(iota_sdk.NameFormatAt))
	}

	limit := int32(10)
	registrations, err := client.IotaNamesRegistrations(
		resolvedAddress,
		iota_sdk.PaginationFilter{Direction: iota_sdk.DirectionForward, Limit: &limit},
	)
	if err != nil {
		log.Fatalf("Failed to fetch registrations: %v", err)
	}

	if len(registrations.Data) == 0 {
		fmt.Println("No IOTA Names registrations found for this address")
		return
	}

	fmt.Printf("Registrations (%d):\n", len(registrations.Data))
	for _, registration := range registrations.Data {
		fmt.Printf(
			"- %s (id: %s, expires_at_ms: %d)\n",
			registration.NameStr(),
			registration.Id().ToHex(),
			registration.ExpirationTimestampMs(),
		)
	}
}
