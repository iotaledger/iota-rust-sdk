// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk_ffi"
)

const MNEMONIC = "round attack kitchen wink winter music trip tiny nephew hire orange what"

func main() {
	privateKeyEd25519, err := sdk.Ed25519PrivateKeyFromMnemonic(MNEMONIC, nil, nil)
	if err != nil {
		log.Fatalf("Failed to get key from mnemonic: %v", err)
	}
	privateKeyEd25519Bech32, err := privateKeyEd25519.ToBech32()
	if err != nil {
		log.Fatalf("Failed to convert to bech32: %v", err)
	}
	publicKeyEd25519 := privateKeyEd25519.PublicKey()
	flaggedPublicKeyEd25519 := publicKeyEd25519.ToFlaggedBytes()
	addressEd25519 := publicKeyEd25519.DeriveAddress()

	fmt.Println("Ed25519\n---:")
	fmt.Println("Private Key:", privateKeyEd25519Bech32)
	fmt.Println("Public Key:", sdk.Base64Encode(publicKeyEd25519.ToBytes()))
	fmt.Println("Public Key With Flag:", sdk.Base64Encode(flaggedPublicKeyEd25519))
	fmt.Println("Address:", addressEd25519.ToHex())

	privateKeySecp256k1, err := sdk.Secp256k1PrivateKeyFromMnemonic(MNEMONIC, nil, nil)
	if err != nil {
		log.Fatalf("Failed to get key from mnemonic: %v", err)
	}
	privateKeySecp256k1Bech32, err := privateKeySecp256k1.ToBech32()
	if err != nil {
		log.Fatalf("Failed to convert to bech32: %v", err)
	}
	publicKeySecp256k1 := privateKeySecp256k1.PublicKey()
	flaggedPublicKeySecp256k1 := publicKeySecp256k1.ToFlaggedBytes()
	addressSecp256k1 := publicKeySecp256k1.DeriveAddress()

	fmt.Println("\nSecp256k1\n---:")
	fmt.Println("Private Key:", privateKeySecp256k1Bech32)
	fmt.Println("Public Key:", sdk.Base64Encode(publicKeySecp256k1.ToBytes()))
	fmt.Println("Public Key With Flag:", sdk.Base64Encode(flaggedPublicKeySecp256k1))
	fmt.Println("Address:", addressSecp256k1.ToHex())

	privateKeySecp256r1, err := sdk.Secp256r1PrivateKeyFromMnemonic(MNEMONIC, nil, nil)
	if err != nil {
		log.Fatalf("Failed to get key from mnemonic: %v", err)
	}
	privateKeySecp256r1Bech32, err := privateKeySecp256r1.ToBech32()
	if err != nil {
		log.Fatalf("Failed to convert to bech32: %v", err)
	}
	publicKeySecp256r1 := privateKeySecp256r1.PublicKey()
	flaggedPublicKeySecp256r1 := publicKeySecp256r1.ToFlaggedBytes()
	addressSecp256r1 := publicKeySecp256r1.DeriveAddress()

	fmt.Println("\nSecp256r1\n---:")
	fmt.Println("Private Key:", privateKeySecp256r1Bech32)
	fmt.Println("Public Key:", sdk.Base64Encode(publicKeySecp256r1.ToBytes()))
	fmt.Println("Public Key With Flag:", sdk.Base64Encode(flaggedPublicKeySecp256r1))
	fmt.Println("Address:", addressSecp256r1.ToHex())

}
