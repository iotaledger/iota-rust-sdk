// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	// The IOTA system state object owns the validator set and other dynamic
	// fields. It is available on every network including localnet.
	parentObjectId := iota_sdk.AddressSystemState()

	page, err := client.DynamicFields(parentObjectId, nil)
	if err != nil {
		log.Fatalf("Failed to get dynamic fields: %v", err)
	}

	fmt.Printf("Page size: %d\n", len(page.Data))
	if len(page.Data) > 0 {
		fmt.Printf("First field name: %+v\n", page.Data[0].Name)

		// The field value can be large (e.g. the validator set on 0x5), so we
		// print only the first few lines as a preview.
		const previewLines = 15
		valueStr := ""
		if page.Data[0].ValueAsJson != nil {
			valueStr = *page.Data[0].ValueAsJson
		}
		lines := strings.Split(valueStr, "\n")
		truncated := len(lines) > previewLines
		if truncated {
			lines = lines[:previewLines]
		}
		fmt.Printf("First field value (first %d lines):\n", previewLines)
		fmt.Println(strings.Join(lines, "\n"))
		if truncated {
			fmt.Println("... [truncated]")
		}
	}
}
