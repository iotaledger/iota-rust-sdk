// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func objIdFromHex(hex string) *sdk.ObjectId {
	id, err := sdk.ObjectIdFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	return id
}

func addrFromHex(hex string) *sdk.Address {
	address, err := sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func getObject(client *sdk.GraphQlClient, objId *sdk.ObjectId) *sdk.Object {
	obj, err := client.Object(objId, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get object: %v", err)
	}
	if obj == nil {
		log.Fatalf("Missing object: %v", objId)
	}
	return *obj
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	fromAddress := addrFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	toAddress := addrFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	objIds := []*sdk.ObjectId{
		objIdFromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"),
		objIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"),
		objIdFromHex("0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9"),
	}
	objsToTransfer := []*sdk.PtbArgument{}
	for _, objId := range objIds {
		obj := getObject(client, objId)
		objsToTransfer = append(objsToTransfer, sdk.PtbArgumentObjectRef(obj.ObjectRef()))
	}

	gasCoinId := objIdFromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")
	gasCoin := getObject(client, gasCoinId).ObjectRef()

	gasPrice, err := client.ReferenceGasPrice(nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	if gasPrice == nil {
		*gasPrice = uint64(100)
	}

	builder := sdk.TransactionBuilderInit(fromAddress)
	builder.TransferObjects(toAddress, objsToTransfer)
	builder.Gas(gasCoin).GasPrice(*gasPrice).GasBudget(500000000)

	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Signing Digest: %v", txn.SigningDigestHex())
	log.Printf("Txn Bytes: %v", txn.ToBase64())

	res, err := client.DryRunTx(txn, false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to transfer objects: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to transfer objects: %v", *res.Error)
	}

	log.Print("Transfer objects dry run was successful!")
}
