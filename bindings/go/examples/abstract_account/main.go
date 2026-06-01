// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()
	accountId, err := setupAccount(client)
	if err != nil {
		log.Fatalf("Failed to setup account: %v", err)
	}

	fromAddress := accountId.ToAddress()
	toAddress, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	// Fund the sender address for gas payment
	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWaitForFinalized(fromAddress, client)
	if err != nil {
		log.Fatalf("Failed to request coins from faucet: %v", err)
	}

	builder := iota_sdk.NewTransactionBuilder(fromAddress).WithClient(client)
	builder.SendIota(toAddress, iota_sdk.PtbArgumentU64(5000000000))

	moveAuthenticator, err := iota_sdk.NewMoveAuthenticatorBuilder(
		accountId,
		[]*iota_sdk.PtbArgument{
			iota_sdk.PtbArgumentString("hello"),
			iota_sdk.PtbArgumentShared(iota_sdk.ObjectIdClock()),
		},
		[]*iota_sdk.TypeTag{},
	).Finish(client)
	if err != nil {
		log.Fatalf("Failed to finish move authenticator: %v", err)
	}

	signer := iota_sdk.TransactionSignerFromMoveAuthenticator(moveAuthenticator)
	waitFor := iota_sdk.WaitForTxFinalized
	effects, err := builder.Execute(signer, &waitFor)
	if err != nil {
		log.Fatalf("Failed to execute transaction: %v", err)
	}

	fmt.Printf("Sending IOTA via abstract account: %v\n", (*effects).AsV1().Status)
}

func setupAccount(client *iota_sdk.GraphQlClient) (*iota_sdk.ObjectId, error) {
	// Parse the precompiled move package
	packageData, err := iota_sdk.MovePackageDataFromJson(PRECOMPILED_PACKAGE)
	if err != nil {
		return nil, fmt.Errorf("failed to parse package data: %w", err)
	}

	// Create a random private key to derive a sender address
	privateKey := iota_sdk.Ed25519PrivateKeyGenerate()
	sender := privateKey.PublicKey().DeriveAddress()

	// Fund the sender address for gas payment
	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWaitForFinalized(sender, client)
	if err != nil {
		return nil, fmt.Errorf("failed to request coins from faucet: %w", err)
	}

	// Build the `publish` PTB
	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)
	// Publish the package and receive the upgrade cap
	builder.Publish(packageData, "upgrade_cap")
	// Transfer the upgrade cap to the sender address
	builder.TransferObjects(sender, []*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("upgrade_cap")})

	// Sign and execute the transaction (publish the package)
	signer := iota_sdk.TransactionSignerFromEd25519(privateKey)
	waitFor := iota_sdk.WaitForTxFinalized
	effects, err := builder.Execute(signer, &waitFor)
	if err != nil {
		return nil, fmt.Errorf("failed to execute transaction: %w", err)
	}

	fmt.Printf("Publishing package: %v\n\n", (*effects).AsV1().Status)

	// Get package, package metadata and account IDs from the effects
	var packageId *iota_sdk.ObjectId
	var packageMetadataId *iota_sdk.ObjectId
	var accountId *iota_sdk.ObjectId

	for _, changedObj := range (*effects).AsV1().ChangedObjects {
		if _, ok := changedObj.OutputState.(iota_sdk.ObjectOutPackageWrite); ok {
			packageId = changedObj.ObjectId
		} else if _, ok := changedObj.OutputState.(iota_sdk.ObjectOutObjectWrite); ok {
			objectId := changedObj.ObjectId
			objPtr, err := client.Object(objectId, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get object: %w", err)
			}

			if objPtr != nil {
				obj := *objPtr
				if obj.AsStructOpt() != nil {
					typeName := obj.AsStruct().StructType.Name().String()
					if typeName == "PackageMetadataV1" {
						packageMetadataId = objectId
					}
					if typeName == "Account" {
						accountId = objectId
					}
				}
			}
		}
	}

	if packageId == nil {
		return nil, fmt.Errorf("missing package id")
	}
	if packageMetadataId == nil {
		return nil, fmt.Errorf("missing package metadata id")
	}
	if accountId == nil {
		return nil, fmt.Errorf("missing account id")
	}

	fmt.Printf("Package ID: %s\n", packageId.ToHex())
	fmt.Printf("PackageMetadataV1 ID: %s\n", packageMetadataId.ToHex())
	fmt.Printf("Account ID: %s\n\n", accountId.ToHex())

	// Build the `link_auth` PTB
	accountModule, _ := iota_sdk.NewIdentifier("account")
	linkAuthFn, _ := iota_sdk.NewIdentifier("link_auth")

	builder = iota_sdk.NewTransactionBuilder(sender).WithClient(client)
	builder.MoveCall(
		packageId.ToAddress(),
		accountModule,
		linkAuthFn,
		[]*iota_sdk.PtbArgument{
			iota_sdk.PtbArgumentSharedMut(accountId),
			iota_sdk.PtbArgumentObjectId(packageMetadataId),
			iota_sdk.PtbArgumentString("account"),
			iota_sdk.PtbArgumentString("authenticate"),
		},
		nil,
		nil,
	)

	// Sign and execute the transaction (link the authenticator)
	effects, err = builder.Execute(signer, &waitFor)
	if err != nil {
		return nil, fmt.Errorf("failed to execute transaction: %w", err)
	}

	fmt.Printf("Linking account to authenticate method: %v\n\n", (*effects).AsV1().Status)

	return accountId, nil
}

// The package below, compiled and exported using `iota move build --dump-bytecode-as-base64`
const PRECOMPILED_PACKAGE = `{"modules":["oRzrCwYAAAALAQAUAhQmAzorBGUGBWtPB7oBwAII+gNgBtoECRDjBCoKjQULDJgFQgAJAgkCCwINAg4CFgIXAhoCGwEKAAEMAAAAAgACAgIAAwMHAQgBBAQIAAUIBAAGBQgACAcCAAkGBwAAEwABAAAUAgEAAAwDAQABDwsBAQgDEAkKAQgFFQQFAAcYBwEBDAkZDA0ABgYEBgMGAggBBwgHAAQIAAYIBggICAgFBggACAgGCAQGCAIGCAcBBwgHAQgFAQgAAQkAAQsDAQgAAwYIBggICAgBCwMBCQACCQALAwEJAAEKAgEICAdBQ0NPVU5UB0FjY291bnQLQXV0aENvbnRleHQaQXV0aGVudGljYXRvckZ1bmN0aW9uUmVmVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlFmF1dGhlbnRpY2F0b3JfZnVuY3Rpb24FY2xvY2sRY3JlYXRlX2FjY291bnRfdjEbY3JlYXRlX2F1dGhfZnVuY3Rpb25fcmVmX3YxC2R1bW15X2ZpZWxkAmlkBGluaXQJbGlua19hdXRoA25ldwZvYmplY3QQcGFja2FnZV9tZXRhZGF0YRNwdWJsaWNfc2hhcmVfb2JqZWN0BnN0cmluZwh0cmFuc2Zlcgp0eF9jb250ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCgIGBWhlbGxvDmlvdGE6Om1ldGFkYXRhGgEAAAAAAAAAEQEMYXV0aGVudGljYXRlAQABAAIBEggFAQIBEQEAAAAAAQULAREFEgA4AAIBAQAACAkLAQsCCwM4AQwECwALBDgCAgIBAAABCQsBBwARByEEBgUIBgAAAAAAAAAAJwIA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[236,68,86,252,91,28,224,206,146,112,120,93,47,52,14,168,169,132,252,75,45,104,10,116,171,91,155,100,66,111,66,147]}`

//nolint:unused
const PACKAGE = `
module account::account;
...
`
