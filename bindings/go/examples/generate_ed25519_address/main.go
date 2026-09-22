// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	privateKey := iota_sdk.Ed25519PrivateKeyRandom()
	privateKeyBech32, err := privateKey.ToBech32()
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey()
	flaggedPublicKey := publicKey.ToFlaggedBytes()
	address := publicKey.DeriveAddress()

	fmt.Println("Private Key:", privateKeyBech32)
	fmt.Println("Public Key:", iota_sdk.Base64Encode(publicKey.ToBytes()))
	fmt.Println("Public Key With Flag:", iota_sdk.Base64Encode(flaggedPublicKey))
	fmt.Println("Address:", address.ToHex())
}
