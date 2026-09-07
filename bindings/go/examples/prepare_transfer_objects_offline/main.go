// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func addrFromHex(hex string) *iota_sdk.Address {
	address, err := iota_sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	privateKey, err := iota_sdk.NewEd25519PrivateKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}
	fromAddress := privateKey.PublicKey().DeriveAddress()

	toAddress := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	faucet := iota_sdk.FaucetClientNewLocalnet()
	if _, err := faucet.RequestAndWaitForFinalized(fromAddress, client); err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	objectFilter := iota_sdk.ObjectFilter{Owner: &fromAddress}
	coinsPage, err := client.Objects(&objectFilter, nil)
	if err != nil {
		log.Fatalf("Failed to get owned objects: %v", err)
	}
	coins := coinsPage.Data
	if len(coins) == 0 {
		log.Fatal("No coins found")
	}
	gasCoin := coins[0].ObjectRef()
	objsToTransfer := []*iota_sdk.PtbArgument{}
	for _, coin := range coins[1:] {
		objsToTransfer = append(objsToTransfer, iota_sdk.PtbArgumentObjectRef(coin.ObjectRef()))
	}

	gasPrice, err := client.ReferenceGasPrice(nil)
	if err != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	if gasPrice == nil {
		*gasPrice = uint64(100)
	}

	builder := iota_sdk.NewTransactionBuilder(fromAddress)
	builder.TransferObjects(toAddress, objsToTransfer)
	builder.Gas([]iota_sdk.ObjectReference{gasCoin}).GasPrice(*gasPrice).GasBudget(500000000)

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTransaction(txn, false)
	if err != nil {
		log.Fatalf("Failed to transfer objects: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to transfer objects: %v", *res.Error)
	}

	log.Print("Transfer objects dry run was successful!")
}
