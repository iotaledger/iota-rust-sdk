// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	recipientAddress, err := sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	privateKey, err := sdk.NewEd25519PrivateKey(make([]byte, 32))
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}
	publicKey := privateKey.PublicKey()
	senderAddress := publicKey.DeriveAddress()
	log.Printf("Sender address: %s", senderAddress.ToHex())

	// Request funds from faucet
	faucet := sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWait(senderAddress)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	client := sdk.GraphQlClientNewLocalnet()

	builder := sdk.TransactionBuilderInit(senderAddress, client)
	builder.SendIota(recipientAddress, sdk.PtbArgumentU64(1000))
	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	dryRunResult, err := client.DryRunTx(txn, false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to dry run: %v", err)
	}
	if dryRunResult.Error != nil {
		log.Fatalf("Dry run failed: %v", *dryRunResult.Error)
	}

	signature, err := privateKey.TrySignSimple(txn.SigningDigest())
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	userSignature := sdk.UserSignatureNewSimple(signature)

	effects, err := client.ExecuteTx([]*sdk.UserSignature{userSignature}, txn)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to execute: %v", err)
	}
	if effects == nil {
		log.Fatalf("Transaction execution failed")
	}
	log.Printf("Digest: %s", sdk.HexEncode((*effects).Digest().ToBytes()))
	log.Printf("Transaction status: %v", (*effects).AsV1().Status)
	log.Printf("Effects: %+v", (*effects).AsV1())
}
