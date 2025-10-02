// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender, _ := sdk.AddressFromHex("0x0")

	iotaNamesPackageAddress, _ := sdk.AddressFromHex("0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba")

	iotaNamesObjectId, _ := sdk.ObjectIdFromHex("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")

	stdlibAddress, _ := sdk.AddressFromHex("0x1")

	name := "name.iota"
	fmt.Printf("Looking up name: %s\n", name)

	builder := sdk.TransactionBuilderInit(sender, client)

	// Create identifiers
	iotaNamesModule, _ := sdk.NewIdentifier("iota_names")
	nameModule, _ := sdk.NewIdentifier("name")
	nameNewFn, _ := sdk.NewIdentifier("new")
	lookupFn, _ := sdk.NewIdentifier("lookup")
	optionModule, _ := sdk.NewIdentifier("option")
	borrowFn, _ := sdk.NewIdentifier("borrow")
	targetAddressFn, _ := sdk.NewIdentifier("target_address")
	registryModule, _ := sdk.NewIdentifier("registry")
	registryName, _ := sdk.NewIdentifier("Registry")

	registryType := sdk.NewStructTag(iotaNamesPackageAddress, registryModule, registryName, []*sdk.TypeTag{})

	nameRecordModule, _ := sdk.NewIdentifier("name_record")
	nameRecordName, _ := sdk.NewIdentifier("NameRecord")
	nameRecordType := sdk.NewStructTag(iotaNamesPackageAddress, nameRecordModule, nameRecordName, []*sdk.TypeTag{})

	// 1. Get the registry
	builder.MoveCall(
		iotaNamesPackageAddress,
		iotaNamesModule,
		registryModule,
		[]*sdk.PtbArgument{sdk.PtbArgumentSharedMut(iotaNamesObjectId)},
		[]*sdk.TypeTag{sdk.TypeTagNewStruct(registryType)},
		[]string{"iota_names"},
	)

	// 2. Create name from string
	builder.MoveCall(
		iotaNamesPackageAddress,
		nameModule,
		nameNewFn,
		[]*sdk.PtbArgument{sdk.PtbArgumentString(name)},
		nil,
		[]string{"name"},
	)

	// 3. Lookup name record
	builder.MoveCall(
		iotaNamesPackageAddress,
		registryModule,
		lookupFn,
		[]*sdk.PtbArgument{sdk.PtbArgumentRes("iota_names"), sdk.PtbArgumentRes("name")},
		nil,
		[]string{"name_record_opt"},
	)

	// 4. Borrow name record from option
	builder.MoveCall(
		stdlibAddress,
		optionModule,
		borrowFn,
		[]*sdk.PtbArgument{sdk.PtbArgumentRes("name_record_opt")},
		[]*sdk.TypeTag{sdk.TypeTagNewStruct(nameRecordType)},
		[]string{"name_record"},
	)

	// 5. Get target address from name record
	builder.MoveCall(
		iotaNamesPackageAddress,
		nameRecordModule,
		targetAddressFn,
		[]*sdk.PtbArgument{sdk.PtbArgumentRes("name_record")},
		nil,
		[]string{"target_address_opt"},
	)

	// 6. Borrow address from option
	builder.MoveCall(
		stdlibAddress,
		optionModule,
		borrowFn,
		[]*sdk.PtbArgument{sdk.PtbArgumentRes("target_address_opt")},
		[]*sdk.TypeTag{sdk.TypeTagNewAddress()},
		[]string{"target_address"},
	)

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
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
				resolvedAddress, err := sdk.AddressFromBytes(returnValue.Bcs)
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
