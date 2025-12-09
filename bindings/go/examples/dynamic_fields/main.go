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

	parentObjectId, err := iota_sdk.AddressFromHex("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	page, err := client.DynamicFields(parentObjectId, nil)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get dynamic fields: %v", err)
	}

	fmt.Printf("Page size: %d\n", len(page.Data))
	if len(page.Data) > 0 {
		fmt.Printf("First field name: %+v\n", page.Data[0].Name)
		fmt.Printf("First field value: %v\n", *page.Data[0].ValueAsJson)
	}
}
