// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

type AsyncSigner struct {
	ledger *iota_sdk.LedgerSigner
}

func (signer *AsyncSigner) Sign(transaction *iota_sdk.Transaction) (iota_sdk.TransactionSignerFnOutput, error) {
	fmt.Println("BEFORE")
	signature, err := signer.ledger.SignTransaction(transaction)
		if err.(*iota_sdk.LedgerSignerError) != nil {
		log.Fatalf("Failed to execute: %v", err)
	}
	fmt.Println("AFTER")
	return iota_sdk.TransactionSignerFnOutput{Signature: signature}, err
}

func main() {
	ledger, err := iota_sdk.LedgerSignerNewWithDefault("m/44'/4218'/0'/1'/0'")

	if err != nil {
		log.Fatalf("Failed to create ledger: %v", err)
	}

	address, err := ledger.GetAddress()

	if err != nil {
		log.Fatalf("Failed to get address: %v", err)
	}

	fmt.Println("Address:", address.ToHex())

	// Request funds from faucet
	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWait(address)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	client := iota_sdk.GraphQlClientNewLocalnet()

	recipientAddress, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	builder := iota_sdk.NewTransactionBuilder(address).WithClient(client)
	builder.SendIota(recipientAddress, iota_sdk.PtbArgumentU64(1000))

	signer := iota_sdk.NewTransactionSigner(&AsyncSigner{ledger: ledger})
	waitFor := iota_sdk.WaitForTxFinalized
	effects, err := builder.Execute(signer, &waitFor)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to execute: %v", err)
	}
	log.Printf("Digest: %s", iota_sdk.HexEncode((*effects).Digest().ToBytes()))
	log.Printf("Transaction status: %v", (*effects).AsV1().Status)
	log.Printf("Effects: %+v", (*effects).AsV1())
}
