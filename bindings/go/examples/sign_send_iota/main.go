// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	// Amount to send in nanos
	amount := uint64(1000)
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
	faucet := sdk.FaucetClientNewLocal()
	_, err = faucet.RequestAndWait(senderAddress)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	client := sdk.GraphQlClientNewLocalhost()
	// Get coins for the sender address
	coinsPage, err := client.Coins(senderAddress, nil, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get coins: %v", err)
	}
	if len(coinsPage.Data) == 0 {
		log.Fatalf("No coins found")
	}
	gasCoin := coinsPage.Data[0]

	gasObject, err := client.Object(gasCoin.Id(), nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas object: %v", err)
	}
	if gasObject == nil {
		log.Fatalf("Missing gas object")
	}

	builder := sdk.TransactionBuilderInit(senderAddress, client)

	// Split the amount from the gas coin
	builder.SplitCoins(gasCoin.Id(), []uint64{amount}, []string{"coin1"})

	// Transfer the split coin
	builder.TransferObjects(recipientAddress, []*sdk.PtbArgument{sdk.PtbArgumentRes("coin1")})

	builder.Gas(gasCoin.Id()).GasBudget(50000000)
	gasPrice, err := client.ReferenceGasPrice(nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	builder.GasPrice(*gasPrice)

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	dryRunResult, err := client.DryRunTx(txn, nil)
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
