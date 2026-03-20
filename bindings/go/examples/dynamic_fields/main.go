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

	parentObjectId, err := iota_sdk.AddressFromHex("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	page, err := client.DynamicFields(parentObjectId, nil)
	if err != nil {
		log.Fatalf("Failed to get dynamic fields: %v", err)
	}

	fmt.Printf("Page size: %d\n", len(page.Data))
	if len(page.Data) > 0 {
		fmt.Printf("First field name: %+v\n", page.Data[0].Name)
		fmt.Printf("First field value: %v\n", *page.Data[0].ValueAsJson)
	}
}
