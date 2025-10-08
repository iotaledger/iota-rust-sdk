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
	address := publicKey.DeriveAddress()
	publicKeyBytes := publicKey.ToBytes()

	flaggedPublicKey := append([]byte{byte(sdk.SignatureSchemeEd25519)}, publicKeyBytes...)

	fmt.Println("Private Key:", privateKeyBech32)
	fmt.Println("Public Key:", sdk.Base64Encode(publicKeyBytes))
	fmt.Println("Public Key With Flag:", sdk.Base64Encode(flaggedPublicKey))
	fmt.Println("Address:", address.ToHex())
}
