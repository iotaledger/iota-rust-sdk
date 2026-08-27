// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	// Amount to send in nanos
	recipientAddress, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	privateKey, err := iota_sdk.NewEd25519PrivateKey(make([]byte, 32))
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}
	senderAddress := privateKey.PublicKey().DeriveAddress()
	log.Printf("Sender address: %s", senderAddress.ToHex())

	// Request funds from faucet (the faucet client relies on GraphQL to await
	// finalization)
	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWaitForFinalized(senderAddress, iota_sdk.GraphQlClientNewLocalnet())
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	client, err := iota_sdk.GrpcClientNewLocalnet()
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	// Resolve gas and build the transaction via gRPC
	builder := iota_sdk.NewTransactionBuilder(senderAddress).WithGrpcClient(client)
	builder.SendIota(recipientAddress, iota_sdk.PtbArgumentU64(1000))
	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	signature, err := privateKey.TrySignSimple(txn.SigningDigest())
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	userSignature := iota_sdk.UserSignatureNewSimple(signature)
	signedTransaction := iota_sdk.SignedTransaction{
		Transaction: txn,
		Signatures:  []*iota_sdk.UserSignature{userSignature},
	}

	executed, err := client.ExecuteTransaction(signedTransaction, nil, nil)
	if err != nil {
		log.Fatalf("Failed to execute: %v", err)
	}

	log.Printf("Digest: %s", iota_sdk.HexEncode((*executed.Digest).ToBytes()))
	switch status := (*executed.Effects).AsV1().Status.(type) {
	case iota_sdk.ExecutionStatusSuccess:
		log.Printf("Transaction status: success")
	case iota_sdk.ExecutionStatusFailure:
		log.Fatalf("Transaction failed: %v", status.Error)
	}
}
