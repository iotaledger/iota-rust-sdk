// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example allows you to publish any Move package by compiling it
// first using the `iota` binary. For demonstration purposes this example
// immediately upgrades the package after publishing it.
//
// bash:
//	 cd /path/to/your/move/package
//   export COMPILED_PACKAGE=$(iota move build --dump-bytecode-as-base64)
//
// fish:
//   cd /path/to/your/move/package
//   set -x COMPILED_PACKAGE (iota move build --dump-bytecode-as-base64)
//
// With this example it is necessary to run a localnet:
//
//   iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	// Read and parse the compiled package, or use the default package
	packageDataString := os.Getenv("COMPILED_PACKAGE")
	if packageDataString == "" {
		fmt.Println("No compiled package found in env var. Using default.")
		packageDataString = PRECOMPILED_PACKAGE
	} else {
		fmt.Println("Using custom Move package found in env var.")
	}

	packageData, err := iota_sdk.MovePackageDataFromJson(packageDataString)
	if err != nil {
		log.Fatalf("Failed to deserialize Move package data: %v", err)
	}
	modules := packageData.Modules()
	fmt.Printf("Modules: %d\n", len(modules))
	dependencies := packageData.Dependencies()
	fmt.Printf("Dependencies: %d\n", len(dependencies))
	digest := packageData.Digest()
	fmt.Printf("Digest: %s\n", digest.ToBase58())

	// Create a random private key to derive a sender address and for signing
	privateKey := iota_sdk.Ed25519PrivateKeyRandom()
	publicKey := privateKey.PublicKey()
	sender := publicKey.DeriveAddress()
	fmt.Printf("Sender: %s\n", sender.ToHex())

	client := iota_sdk.GraphQlClientNewLocalnet()

	// Fund the sender address for gas payment
	faucet := iota_sdk.FaucetClientNewLocalnet()
	faucetReceipt, err := faucet.RequestAndWaitForFinalized(sender, client)
	if err != nil {
		log.Fatalf("Failed to request coins from faucet: %v", err)
	}
	totalBalance := uint64(0)
	for _, coin := range faucetReceipt.Sent {
		totalBalance += coin.Amount
	}

	// Build the `publish` PTB
	builderPublish := client.TransactionBuilder(sender)
	// Publish the package and receive the upgrade cap in return
	builderPublish.PublishPackage(packageData, "upgrade_cap")
	// Transfer the upgrade cap to the sender address
	builderPublish.TransferObjects(sender, []*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("upgrade_cap")})
	txPublish, err := builderPublish.Finish()
	if err != nil {
		log.Fatalf("Failed to finish transaction: %v", err)
	}

	// Perform a dry-run first to check if everything is correct
	fmt.Println("> Publishing package (dry run):")
	resultPublish, err := client.DryRunTransaction(txPublish, false)
	if err != nil {
		log.Fatalf("Dry run failed: %v", err)
	}
	if resultPublish.Error != nil {
		log.Fatalf("Dry run failed: %v", *resultPublish.Error)
	}
	if resultPublish.Effects == nil {
		log.Fatal("Dry run failed: no effects")
	}
	fmt.Println("Success")

	// Sign and execute the transaction (publish the package)
	fmt.Println("> Publishing package:")
	userSigPublish, err := privateKey.SignTransaction(txPublish)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	waitFor := iota_sdk.WaitForTransactionFinalized
	effectsPublish, err := client.ExecuteTransaction([]*iota_sdk.UserSignature{userSigPublish}, txPublish, &waitFor)
	if err != nil {
		log.Fatalf("Transaction failed: %v", err)
	}
	fmt.Println("Success")

	// Resolve UpgradeCap and PackageId via the client
	var upgradeCap *iota_sdk.ObjectId
	var packageId *iota_sdk.ObjectId
	for _, changedObj := range (*effectsPublish).AsV1().ChangedObjects() {
		if objectWrite, ok := changedObj.OutputState.(iota_sdk.ObjectOutObjectWrite); ok {
			objectId := changedObj.ObjectId
			objPtr, err := client.Object(objectId, nil)
			if err != nil {
				log.Fatalf("Failed to get object: %v", err)
			}
			obj := *objPtr
			if obj.AsOptStruct() != nil {
				upgradeCapType := iota_sdk.StructTagNewUpgradeCap()
				if obj.AsStruct().StructType.Eq(upgradeCapType) {
					fmt.Printf("UpgradeCap: %s\n", objectId.ToHex())
					fmt.Printf("UpgradeCapOwner: %s\n", objectWrite.Owner.AsAddress().ToHex())
					upgradeCap = objectId
				}
			}
		} else if _, ok := changedObj.OutputState.(iota_sdk.ObjectOutPackageWrite); ok {
			pkgId := changedObj.ObjectId
			fmt.Printf("Package ID: %s\n", pkgId.ToHex())
			version := changedObj.OutputState.(iota_sdk.ObjectOutPackageWrite).Version
			fmt.Printf("Package version: %d\n", version)
			packageId = pkgId
		}
	}
	if upgradeCap == nil {
		log.Fatal("Missing upgrade cap")
	}
	if packageId == nil {
		log.Fatal("Missing package id")
	}

	// Build the `upgrade` PTB
	builderUpgrade := client.TransactionBuilder(sender)

	// Authorize the upgrade by providing the upgrade cap object id to receive an upgrade
	// ticket
	upgradeTicketName := "upgrade_ticket"
	packageIdent, _ := iota_sdk.NewIdentifier("package")
	authorizeUpgrade, _ := iota_sdk.NewIdentifier("authorize_upgrade")
	upgradeCapArg := iota_sdk.PtbArgumentObjectId(upgradeCap)
	upgradePolicy := iota_sdk.PtbArgumentU8(iota_sdk.UpgradePolicyCompatible().AsU8())
	builderUpgrade.MoveCall(
		iota_sdk.AddressFramework(),
		packageIdent,
		authorizeUpgrade,
		[]*iota_sdk.PtbArgument{upgradeCapArg, upgradePolicy, iota_sdk.PtbArgumentU8Vec(digest.ToBytes())},
		nil,
		[]string{upgradeTicketName},
	)

	// Upgrade the package to receive an upgrade receipt
	upgradeReceiptName := "upgrade_receipt"
	builderUpgrade.Upgrade(packageId, packageData, iota_sdk.PtbArgumentAssigned(upgradeTicketName), &upgradeReceiptName)

	// Commit the upgrade using the receipt
	commitUpgrade, _ := iota_sdk.NewIdentifier("commit_upgrade")
	builderUpgrade.MoveCall(
		iota_sdk.AddressFramework(),
		packageIdent,
		commitUpgrade,
		[]*iota_sdk.PtbArgument{upgradeCapArg, iota_sdk.PtbArgumentAssigned(upgradeReceiptName)},
		nil,
		nil,
	)

	txUpgrade, err := builderUpgrade.Finish()
	if err != nil {
		log.Fatalf("Failed to finish transaction: %v", err)
	}

	// Perform a dry-run first to check if everything is correct
	fmt.Println("> Upgrading package (dry run):")
	resultUpgrade, err := client.DryRunTransaction(txUpgrade, false)
	if err != nil {
		log.Fatalf("Dry run failed: %v", err)
	}
	if resultUpgrade.Error != nil {
		log.Fatalf("Dry run failed: %v", *resultUpgrade.Error)
	}
	if resultUpgrade.Effects == nil {
		log.Fatal("Dry run failed: no effects")
	}
	fmt.Println("Success")

	// Sign and execute the transaction (upgrade the package)
	fmt.Println("> Upgrading package:")
	userSigUpgrade, err := privateKey.SignTransaction(txUpgrade)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	effectsUpgrade, err := client.ExecuteTransaction([]*iota_sdk.UserSignature{userSigUpgrade}, txUpgrade, nil)
	if err != nil {
		log.Fatalf("Transaction failed: %v", err)
	}
	fmt.Println("Success")

	// Print the new package version (should now be 2)
	for _, changedObj := range (*effectsUpgrade).AsV1().ChangedObjects() {
		if _, ok := changedObj.OutputState.(iota_sdk.ObjectOutPackageWrite); ok {
			pkgId := changedObj.ObjectId
			fmt.Printf("New Package ID: %s\n", pkgId.ToHex())
			version := changedObj.OutputState.(iota_sdk.ObjectOutPackageWrite).Version
			fmt.Printf("New Package version: %d\n", version)
		}
	}
}

// Pre-compiled `first_package` example
const PRECOMPILED_PACKAGE = `{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}`
