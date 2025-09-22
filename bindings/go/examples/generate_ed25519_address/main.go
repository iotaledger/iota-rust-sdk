// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"fmt"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	privateKey := sdk.Ed25519PrivateKeyGenerate()
	publicKey := privateKey.PublicKey()
	address := publicKey.DeriveAddress()
	publicKeyBytes := publicKey.ToBytes()

	flaggedPublicKey := append([]byte{byte(sdk.SignatureSchemeEd25519)}, publicKeyBytes...)
	privateKeyDer, err := privateKey.ToDer()
	if err != nil {
		panic(err)
	}

	fmt.Println("Private Key:", base64.StdEncoding.EncodeToString(privateKeyDer))
	fmt.Println("Public Key:", base64.StdEncoding.EncodeToString(publicKeyBytes))
	fmt.Println("Public Key With Flag:", base64.StdEncoding.EncodeToString(flaggedPublicKey))
	fmt.Println("Address:", address.ToHex())
}
