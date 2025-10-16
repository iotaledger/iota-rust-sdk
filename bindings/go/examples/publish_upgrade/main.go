// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"time"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	// Hardcoded values from the JSON
	modules := [][]byte{
		func() []byte {
			b, _ := base64.StdEncoding.DecodeString("oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA")
			return b
		}(),
	}
	dependencies := []*sdk.ObjectId{
		func() *sdk.ObjectId {
			id, _ := sdk.ObjectIdFromHex("0x0000000000000000000000000000000000000000000000000000000000000002")
			return id
		}(),
		func() *sdk.ObjectId {
			id, _ := sdk.ObjectIdFromHex("0x0000000000000000000000000000000000000000000000000000000000000001")
			return id
		}(),
	}
	compiledPackageDigest := []byte{246, 127, 102, 77, 186, 19, 68, 12, 161, 181, 56, 248, 210, 0, 91, 211, 245, 251, 165, 152, 0, 197, 250, 135, 171, 37, 177, 240, 133, 76, 122, 124}
	fmt.Printf("Compiled Package Digest: %x\n", compiledPackageDigest)

	// Create a random private key to derive a sender address and for signing
	privateKey := sdk.Ed25519PrivateKeyGenerate()
	publicKey := privateKey.PublicKey()
	sender := publicKey.DeriveAddress()
	fmt.Printf("Sender: %s\n", sender.ToHex())

	// Fund the sender address for gas payment
	faucet := sdk.FaucetClientNewLocalnet()
	faucetReceipt, err := faucet.RequestAndWait(sender)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to request coins from faucet: %v", err)
	}
	totalBalance := uint64(0)
	for _, coin := range faucetReceipt.Sent {
		totalBalance += coin.Amount
	}
	fmt.Printf("Available Balance: %d\n", totalBalance)

	client := sdk.GraphQlClientNewLocalnet()

	// Build the `publish` PTB, that consists of 2 steps
	builder := sdk.TransactionBuilderInit(sender, client)

	// 1. Create the upgrade cap
	builder.Publish(modules, dependencies, "upgrade_cap")

	// 2. Transfer the upgrade cap to the sender address
	builder.TransferObjects(sender, []*sdk.PtbArgument{sdk.PtbArgumentRes("upgrade_cap")})

	// Finalize the PTB
	tx, err := builder.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to finish transaction: %v", err)
	}

	// Perform a dry-run to check if everything is fine
	result, err := client.DryRunTx(tx, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Dry run failed: %v", err)
	}
	if result.Error != nil {
		log.Fatalf("Dry run failed: %v", *result.Error)
	}
	if result.Effects == nil {
		log.Fatal("Dry run failed: no effects")
	}
	fmt.Printf("Effects status (dry run): %s\n", (*result.Effects).AsV1().Status)

	// Sign and execute the transaction (publish the package)
	fmt.Println("Publishing package")
	signature, err := privateKey.TrySignSimple(tx.SigningDigest())
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	userSignature := sdk.UserSignatureNewSimple(signature)
	effects, err := client.ExecuteTx([]*sdk.UserSignature{userSignature}, tx)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Transaction failed: %v", err)
	}
	if effects == nil {
		log.Fatal("Transaction failed: no effects")
	}
	fmt.Printf("Effects status (publish): %s\n", (*effects).AsV1().Status)

	// Wait some time for the indexer to process the tx
	time.Sleep(10 * time.Second)

	// Resolve UpgradeCap and PackageId via the client
	var upgradeCap *sdk.ObjectId
	var packageId *sdk.ObjectId

	for _, changedObj := range (*effects).AsV1().ChangedObjects {
		if _, ok := changedObj.OutputState.(sdk.ObjectOutObjectWrite); ok {
			objectId := changedObj.ObjectId
			objPtr, err := client.Object(objectId, nil)
			if err.(*sdk.SdkFfiError) != nil {
				log.Fatalf("Failed to get object: %v", err)
			}
			obj := *objPtr
			if obj.AsStructOpt() != nil {
				structType := obj.AsStructOpt().StructType
				packageIdent, _ := sdk.NewIdentifier("package")
				upgradeCapIdent, _ := sdk.NewIdentifier("UpgradeCap")
				upgradeCapType := sdk.NewStructTag(sdk.AddressFramework(), packageIdent, upgradeCapIdent, []*sdk.TypeTag{})
				if structType.String() == upgradeCapType.String() {
					upgradeCap = objectId
				}
			}
		} else if _, ok := changedObj.OutputState.(sdk.ObjectOutPackageWrite); ok {
			pkgId := changedObj.ObjectId
			if packageId == nil {
				packageId = pkgId
			}
		}
	}

	if upgradeCap == nil {
		log.Fatal("Missing upgrade cap")
	}
	if packageId == nil {
		log.Fatal("Missing package id")
	}

	// Build the `upgrade` PTB, that consists of 3 steps
	builder2 := sdk.TransactionBuilderInit(sender, client)

	upgradeCapArg := sdk.PtbArgumentObjectId(upgradeCap)

	// 1. Create the upgrade ticket
	authorizeUpgrade, err := sdk.NewIdentifier("authorize_upgrade")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	packageIdent, err := sdk.NewIdentifier("package")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	builder2.MoveCall(
		sdk.AddressFramework(),
		packageIdent,
		authorizeUpgrade,
		[]*sdk.PtbArgument{upgradeCapArg, sdk.PtbArgumentU8(0), sdk.PtbArgumentU8Vec(compiledPackageDigest)},
		nil,
		[]string{"upgrade_ticket"},
	)

	// 2. Get the upgrade receipt
	upgradeReceiptName := "upgrade_receipt"
	builder2.Upgrade(modules, dependencies, packageId, sdk.PtbArgumentRes("upgrade_ticket"), &upgradeReceiptName)

	// 3. Finalize the upgrade
	commitUpgrade, err := sdk.NewIdentifier("commit_upgrade")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	builder2.MoveCall(
		sdk.AddressFramework(),
		packageIdent,
		commitUpgrade,
		[]*sdk.PtbArgument{upgradeCapArg, sdk.PtbArgumentRes("upgrade_receipt")},
		nil,
		nil,
	)

	// Finalize the PTB
	tx2, err := builder2.Finish()
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to finish transaction: %v", err)
	}

	// Perform a dry-run to check if everything is fine
	result2, err := client.DryRunTx(tx2, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Dry run failed: %v", err)
	}
	if result2.Error != nil {
		log.Fatalf("Dry run failed: %v", *result2.Error)
	}
	if result2.Effects == nil {
		log.Fatal("Dry run failed: no effects")
	}
	fmt.Printf("Effects status (dry run): %s\n", (*result2.Effects).AsV1().Status)

	// Sign and execute the transaction (upgrade the package)
	fmt.Println("Upgrading package")
	signature2, err := privateKey.TrySignSimple(tx2.SigningDigest())
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	userSignature2 := sdk.UserSignatureNewSimple(signature2)
	effects2, err := client.ExecuteTx([]*sdk.UserSignature{userSignature2}, tx2)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Transaction failed: %v", err)
	}
	if effects2 == nil {
		log.Fatal("Transaction failed: no effects")
	}
	fmt.Printf("Effects status (upgrade): %s\n", (*effects2).AsV1().Status)

	// Wait some time for the indexer to process the tx
	time.Sleep(10 * time.Second)

	// Print the new package version (should now be 2)
	for _, changedObj := range (*effects2).AsV1().ChangedObjects {
		if _, ok := changedObj.OutputState.(sdk.ObjectOutPackageWrite); ok {
			pkgId := changedObj.ObjectId
			version := changedObj.OutputState.(sdk.ObjectOutPackageWrite).Version
			fmt.Printf("PackageId: %s\n", pkgId.ToHex())
			fmt.Printf("Package version: %d\n", version)
		}
	}
}
