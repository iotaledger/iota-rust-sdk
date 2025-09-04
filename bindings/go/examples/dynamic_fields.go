// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func isNilError(err error) bool {
	if sdkErr, ok := err.(*sdk.SdkFfiError); ok {
		return sdkErr == nil
	}
	return false
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	parentObjectId, err := sdk.AddressFromHex("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	pagination := sdk.PaginationFilter{
		Direction: sdk.DirectionForward,
		Cursor:    nil,
		Limit:     nil,
	}

	page, err := client.DynamicFields(parentObjectId, pagination)
	if !isNilError(err) {
		log.Fatalf("Failed to get dynamic fields: %v", err)
	}

	fmt.Printf("Page info: %+v\n", page.PageInfo)
	fmt.Printf("Page size: %d\n", len(page.Data))
	if len(page.Data) > 0 {
		fmt.Printf("First field name: %+v\n", page.Data[0].Name)
		fmt.Printf("First field value: %v\n", *page.Data[0].ValueAsJson)
	}
}
