// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	mnemonic := iota_sdk.GenerateMnemonic(nil)
	fmt.Println("24 word mnemonic:", mnemonic)
	wordCount := iota_sdk.MnemonicWordCountWords12
	mnemonic = iota_sdk.GenerateMnemonic(&wordCount)
	fmt.Println("12 word mnemonic:", mnemonic)
}
