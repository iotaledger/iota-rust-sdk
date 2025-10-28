// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewTestnet()

	// some fix values on Testnet
	privateKeyHex := "0032e67709569b6a1ef551ea7a745aac943b2158fc862ae7c6d08dd1744e15d818"
	senderAddressHex := "0x786dff8a4ee13d45b502c8f22f398e3517e6ec78aa4ae564c348acb07fad7f50"
	coinObjectIdHex := "0x7714345721694a20c6e2e04a6a289b1c08710cda863f7dd49b4661cde524103d"
	gasObjectIdHex := "0xd7913b6c9c1e67c281ad13bffcb4d172ffb8f5a85581e5d5984eacb310365be8"

	// Load keypair from hex using SimpleKeypair
	privateKeyBytes, err := sdk.HexDecode(privateKeyHex)
	if err != nil {
		log.Fatalf("Failed to decode private key: %v", err)
	}

	simpleKeypair, err := sdk.SimpleKeypairFromBytes(privateKeyBytes)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	fromAddress, _ := sdk.AddressFromHex(senderAddressHex)
	toAddress, _ := sdk.AddressFromHex(senderAddressHex)
	coinObjId, _ := sdk.ObjectIdFromHex(coinObjectIdHex)
	gasCoinObjId, _ := sdk.ObjectIdFromHex(gasObjectIdHex)

	log.Printf("Building transaction from %s to %s\n", fromAddress.ToHex(), toAddress.ToHex())

	// Build the transaction
	builder := sdk.TransactionBuilderInit(fromAddress, client)
	builder.TransferObjects(toAddress, []*sdk.PtbArgument{sdk.PtbArgumentObjectId(coinObjId)})
	builder.Gas(gasCoinObjId).GasBudget(1000000000)

	// Finish building to get the transaction
	txn, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to build transaction: %v", err)
	}

	log.Printf("Transaction built, signing with keypair...\n")

	// Sign the transaction using SimpleKeypair
	simpleSignature, err := simpleKeypair.TrySign(txn.SigningDigest())
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	// Convert SimpleSignature to UserSignature
	userSignature := sdk.UserSignatureNewSimple(simpleSignature)

	log.Printf("Transaction signed, executing on-chain...\n")

	// Execute the transaction on-chain
	effects, err := client.ExecuteTx([]*sdk.UserSignature{userSignature}, txn)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("ExecuteTx failed: %v", err)
	}

	if effects == nil {
		log.Println("No transaction effects returned")
		return
	}

	log.Printf("Transaction executed successfully!\n")

	// Access and print transaction effects
	PrintObjectChanges(*effects)
}

func PrintObjectChanges(effects *sdk.TransactionEffects) {
	log.Println("=== Object Changes (from ExecuteTx) ===")

	if !effects.IsV1() {
		log.Panicln("Effects version is not V1")
	}

	effectsV1 := effects.AsV1()
	log.Printf("Total changed objects: %d\n", len(effectsV1.ChangedObjects))

	for i, change := range effectsV1.ChangedObjects {
		log.Printf("Object #%d:\n", i+1)
		log.Printf("  Object ID: %s\n", change.ObjectId.ToHex())

		// Check creation/deletion status using IdOperation
		switch change.IdOperation {
		case sdk.IdOperationCreated:
			log.Println("  Status: CREATED")
		case sdk.IdOperationDeleted:
			log.Println("  Status: DELETED")
		case sdk.IdOperationNone:
			log.Println("  Status: MODIFIED")
		}

		// Object type (if available)
		if change.ObjectType != nil {
			log.Printf("  Type: %s\n", *change.ObjectType)
		} else {
			log.Printf("  Type: %v\n", change.ObjectType)
		}

		// Input state (state before transaction)
		switch input := change.InputState.(type) {
		case sdk.ObjectInMissing:
			log.Println("  Input State: Missing (new object)")
		case sdk.ObjectInData:
			log.Printf("  Input State: Version=%d, Owner=%s\n", input.Version, input.Owner.String())
		}

		// Output state (state after transaction)
		switch output := change.OutputState.(type) {
		case sdk.ObjectOutMissing:
			log.Println("  Output State: Missing (deleted)")
		case sdk.ObjectOutObjectWrite:
			log.Printf("  Output State: ObjectWrite, Owner=%s\n", output.Owner.String())
		case sdk.ObjectOutPackageWrite:
			log.Printf("  Output State: PackageWrite, Version=%d\n", output.Version)
		}
	}
}
