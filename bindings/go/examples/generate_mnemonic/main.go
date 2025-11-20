// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	mnemonic, err := iota_sdk.GenerateMnemonic(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Mnemonic:", mnemonic)
}
