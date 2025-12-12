// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

type AsyncSigner struct {
	Key *iota_sdk.Ed25519PrivateKey
}

func (signer *AsyncSigner) Sign(transaction *iota_sdk.Transaction) (iota_sdk.TransactionSignerFnOutput, error) {
	sig, err := signer.Key.SignTransaction(transaction)
	return iota_sdk.TransactionSignerFnOutput{Sig: sig}, err
}

func main() {
	recipientAddress, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	privateKey, err := iota_sdk.NewEd25519PrivateKey(make([]byte, 32))
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}
	publicKey := privateKey.PublicKey()
	senderAddress := publicKey.DeriveAddress()
	log.Printf("Sender address: %s", senderAddress.ToHex())

	// Request funds from faucet
	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWait(senderAddress)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	client := iota_sdk.GraphQlClientNewLocalnet()

	builder := iota_sdk.NewTransactionBuilder(senderAddress).WithClient(client)
	builder.SendIota(recipientAddress, iota_sdk.PtbArgumentU64(1000))

	waitFor := iota_sdk.WaitForTxFinalized

	effects, err := builder.Execute(iota_sdk.NewTransactionSigner(&AsyncSigner{Key: privateKey}), &waitFor)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to execute: %v", err)
	}
	log.Printf("Digest: %s", iota_sdk.HexEncode((*effects).Digest().ToBytes()))
	log.Printf("Transaction status: %v", (*effects).AsV1().Status)
	log.Printf("Effects: %+v", (*effects).AsV1())
}
