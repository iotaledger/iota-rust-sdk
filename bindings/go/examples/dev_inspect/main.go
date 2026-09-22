// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
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

func identifier(ident string) *iota_sdk.Identifier {
	identifier, err := iota_sdk.NewIdentifier(ident)
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}
	return identifier
}

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	sender := iota_sdk.AddressZero()

	iotaNamesPackageAddress := addrFromHex("0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea")

	iotaNamesObjectId := objIdFromHex("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")

	stdAddress := iota_sdk.AddressStd()

	name := "name.iota"
	fmt.Printf("Looking up name: %s\n", name)

	builder := client.TransactionBuilder(sender)

	// Create identifiers
	iotaNamesModule := identifier("iota_names")
	nameModule := identifier("name")
	nameNewFn := identifier("new")
	lookupFn := identifier("lookup")
	optionModule := identifier("option")
	borrowFn := identifier("borrow")
	targetAddressFn := identifier("target_address")
	registryModule := identifier("registry")
	registryName := identifier("Registry")

	registryType := iota_sdk.NewStructTag(iotaNamesPackageAddress, registryModule, registryName, []*iota_sdk.TypeTag{})

	nameRecordModule := identifier("name_record")
	nameRecordName := identifier("NameRecord")
	nameRecordType := iota_sdk.NewStructTag(iotaNamesPackageAddress, nameRecordModule, nameRecordName, []*iota_sdk.TypeTag{})

	// 1. Get the registry
	builder.MoveCall(
		iotaNamesPackageAddress,
		iotaNamesModule,
		registryModule,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentSharedMut(iotaNamesObjectId)},
		[]*iota_sdk.TypeTag{iota_sdk.TypeTagNewStruct(registryType)},
		[]string{"iota_names"},
	)

	// 2. Create name from string
	builder.MoveCall(
		iotaNamesPackageAddress,
		nameModule,
		nameNewFn,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentString(name)},
		nil,
		[]string{"name"},
	)

	// 3. Lookup name record
	builder.MoveCall(
		iotaNamesPackageAddress,
		registryModule,
		lookupFn,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("iota_names"), iota_sdk.PtbArgumentAssigned("name")},
		nil,
		[]string{"name_record_opt"},
	)

	// 4. Borrow name record from option
	builder.MoveCall(
		stdAddress,
		optionModule,
		borrowFn,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("name_record_opt")},
		[]*iota_sdk.TypeTag{iota_sdk.TypeTagNewStruct(nameRecordType)},
		[]string{"name_record"},
	)

	// 5. Get target address from name record
	builder.MoveCall(
		iotaNamesPackageAddress,
		nameRecordModule,
		targetAddressFn,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("name_record")},
		nil,
		[]string{"target_address_opt"},
	)

	// 6. Borrow address from option
	builder.MoveCall(
		stdAddress,
		optionModule,
		borrowFn,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("target_address_opt")},
		[]*iota_sdk.TypeTag{iota_sdk.TypeTagNewAddress()},
		[]string{"target_address"},
	)

	res, err := builder.DryRun(true)
	if err != nil {
		log.Fatalf("Failed to dry run transaction: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to lookup name: %v", *res.Error)
	}

	// Extract the resolved address from the last result
	if len(res.Results) > 0 {
		lastEffect := res.Results[len(res.Results)-1]
		if len(lastEffect.ReturnValues) > 0 {
			returnValue := lastEffect.ReturnValues[0]
			if returnValue.TypeTag.IsAddress() && len(returnValue.Bcs) == 32 {
				resolvedAddress, err := iota_sdk.AddressFromBytes(returnValue.Bcs)
				if err != nil {
					log.Fatalf("Failed to create address from bytes: %v", err)
				}
				fmt.Printf("Resolved address: %s\n", resolvedAddress.ToHex())
			} else {
				fmt.Printf("Last result is not an address type or has wrong length: %d\n", len(returnValue.Bcs))
			}
		} else {
			fmt.Println("No return value in last effect")
		}
	} else {
		fmt.Println("No results found")
	}
}
