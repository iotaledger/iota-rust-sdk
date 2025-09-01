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

	chainID, err := client.ChainId()
	if !isNilError(err) {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}