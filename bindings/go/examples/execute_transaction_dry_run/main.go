// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

// === DryRun with ObjectChange Example ===
// This example demonstrates the ObjectChange feature using DryRun,
// which simulates transaction execution without actual on-chain changes.
func main() {

	// Initialize client
	client := sdk.GraphQlClientNewDevnet()

	// Use actual addresses from devnet (these are examples)
	fromAddress, _ := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	toAddress, _ := sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

	coinObjId, _ := sdk.ObjectIdFromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")

	gasCoinObjId, _ := sdk.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")

	builder := sdk.TransactionBuilderInit(fromAddress, client)
	builder.TransferObjects(toAddress, []*sdk.PtbArgument{sdk.PtbArgumentObjectId(coinObjId)})
	builder.Gas(gasCoinObjId).GasBudget(1000000000)

	dryRunResult, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Dry run failed: %v", err)
	}

	if dryRunResult.Error != nil {
		log.Fatalf("Dry run returned an error: %s\n", *dryRunResult.Error)
	}

	log.Printf("Dry run succeeded!\n")

	// Access transaction effects from dry run
	if dryRunResult.Effects != nil {
		PrintObjectChanges(*dryRunResult.Effects)
	} else {
		log.Println("No transaction effects available in dry run result")
	}
}

func PrintObjectChanges(effects *sdk.TransactionEffects) {
	log.Println("=== Object Changes (from DryRun) ===")

	if !effects.IsV1() {
		log.Println("Effects version is not V1")
		return
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
