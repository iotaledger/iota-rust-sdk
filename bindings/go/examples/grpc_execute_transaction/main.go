// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	// Amount to send in nanos
	amount := uint64(1000)
	recipientAddress, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	privateKey, err := iota_sdk.NewEd25519PrivateKey(make([]byte, 32))
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}
	senderAddress := privateKey.PublicKey().DeriveAddress()
	log.Printf("Sender address: %s", senderAddress)

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
	builder.SendIota(recipientAddress, iota_sdk.PtbArgumentU64(amount))
	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	// Simulate first: the node runs the transaction without committing it.
	simulated, err := client.SimulateTransaction(txn, false, nil)
	if err != nil {
		log.Fatalf("Failed to simulate: %v", err)
	}
	if simulated.ExecutionError != nil {
		source := ""
		if simulated.ExecutionError.Source != nil {
			source = *simulated.ExecutionError.Source
		}
		log.Printf("Simulation aborted: %s", source)
	} else {
		results := 0
		if simulated.CommandResults != nil {
			results = len(*simulated.CommandResults)
		}
		gasPrice := "none"
		if simulated.SuggestedGasPrice != nil {
			gasPrice = fmt.Sprint(*simulated.SuggestedGasPrice)
		}
		log.Printf("Simulation succeeded: %d command result(s), suggested gas price %s", results, gasPrice)
	}

	signature, err := privateKey.SignTransaction(txn)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	signedTransaction := iota_sdk.SignedTransaction{
		Transaction: txn,
		Signatures:  []*iota_sdk.UserSignature{signature},
	}

	executed, err := client.ExecuteTransaction(signedTransaction, nil, nil)
	if err != nil {
		log.Fatalf("Failed to execute: %v", err)
	}

	if executed.Digest != nil {
		log.Printf("Digest: %s", *executed.Digest)
	}
	if executed.Effects != nil {
		switch status := (*executed.Effects).AsV1().Status().(type) {
		case iota_sdk.ExecutionStatusSuccess:
			log.Printf("Transaction status: success")
		case iota_sdk.ExecutionStatusFailure:
			log.Printf("Transaction status: failure (%v)", status.Error)
		}
	}
}
