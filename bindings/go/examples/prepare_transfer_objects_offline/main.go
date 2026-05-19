// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
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

	fromAddress := addrFromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

	toAddress := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	// Prefetch object refs and gas price online so the rest of the example can
	// be assembled offline.
	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err := faucet.RequestAndWaitForFinalized(fromAddress, client)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	coinType := "0x2::coin::Coin<0x2::iota::IOTA>"
	owned, err := client.Objects(&iota_sdk.ObjectFilter{Owner: &fromAddress, TypeTag: &coinType}, nil)
	if err != nil {
		log.Fatalf("Failed to list owned objects: %v", err)
	}
	if len(owned.Data) < 4 {
		log.Fatal("sender does not own at least 4 coins (1 for gas + 3 to transfer)")
	}
	gasCoin := owned.Data[0].ObjectRef()
	objsToTransfer := []*iota_sdk.PtbArgument{
		iota_sdk.PtbArgumentObjectRef(owned.Data[1].ObjectRef()),
		iota_sdk.PtbArgumentObjectRef(owned.Data[2].ObjectRef()),
		iota_sdk.PtbArgumentObjectRef(owned.Data[3].ObjectRef()),
	}

	gasPrice, err := client.ReferenceGasPrice(nil)
	if err != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	if gasPrice == nil {
		fallback := uint64(100)
		gasPrice = &fallback
	}

	// From here on, no further network calls are made; the transaction is
	// assembled entirely from the prefetched object refs.
	builder := iota_sdk.NewTransactionBuilder(fromAddress)
	builder.TransferObjects(toAddress, objsToTransfer)
	builder.Gas([]iota_sdk.ObjectReference{gasCoin}).GasPrice(*gasPrice).GasBudget(500000000)

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err != nil {
		log.Fatalf("Failed to transfer objects: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to transfer objects: %v", *res.Error)
	}

	log.Print("Transfer objects dry run was successful!")
}
