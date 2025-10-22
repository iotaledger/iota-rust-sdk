// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	privateKey := sdk.Ed25519PrivateKeyGenerate()
	privateKeyBech32, err := privateKey.ToBech32()
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey()
	flaggedPublicKey := publicKey.ToFlaggedBytes()
	address := publicKey.DeriveAddress()

	fmt.Println("Private Key:", privateKeyBech32)
	fmt.Println("Public Key:", sdk.Base64Encode(publicKey.ToBytes()))
	fmt.Println("Public Key With Flag:", sdk.Base64Encode(flaggedPublicKey))
	fmt.Println("Address:", address.ToHex())
}
