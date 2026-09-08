// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func objIdFromHex(hex string) *iota_sdk.ObjectId {
	id, err := iota_sdk.ObjectIdFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	return id
}

func addrFromHex(hex string) *iota_sdk.Address {
	address, err := iota_sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func getObject(client *iota_sdk.GraphQlClient, objId *iota_sdk.ObjectId) *iota_sdk.Object {
	obj, err := client.Object(objId, nil)
	if err != nil {
		log.Fatalf("Failed to get object: %v", err)
	}
	if obj == nil {
		log.Fatalf("Missing object: %v", objId)
	}
	return *obj
}

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	fromAddress := addrFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

	toAddress := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	objIds := []*iota_sdk.ObjectId{
		objIdFromHex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db"),
		objIdFromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc"),
		objIdFromHex("0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2"),
	}
	objsToTransfer := []*iota_sdk.PtbArgument{}
	for _, objId := range objIds {
		obj := getObject(client, objId)
		objsToTransfer = append(objsToTransfer, iota_sdk.PtbArgumentObjectRef(obj.ObjectRef()))
	}

	gasCoinId := objIdFromHex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")
	gasCoin := getObject(client, gasCoinId).ObjectRef()

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
