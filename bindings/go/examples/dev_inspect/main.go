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

	senderAddress, err := sdk.AddressFromHex("0x0")
	if err != nil {
		log.Fatalf("Failed to parse sender address: %v", err)
	}

	iotaNamesPackageAddress, err := sdk.AddressFromHex("0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba")
	if err != nil {
		log.Fatalf("Failed to parse IOTA names package address: %v", err)
	}

	iotaNamesObjectId, err := sdk.ObjectIdFromHex("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")
	if err != nil {
		log.Fatalf("Failed to parse IOTA names object ID: %v", err)
	}

	stdlibAddress, err := sdk.AddressFromHex("0x1")
	if err != nil {
		log.Fatalf("Failed to parse stdlib address: %v", err)
	}

	name := "name.iota"
	fmt.Printf("Looking up name: %s\n", name)

	builder := sdk.NewTransactionBuilder()

	// Create identifiers
	iotaNamesModule, err := sdk.NewIdentifier("iota_names")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	registryFn, err := sdk.NewIdentifier("registry")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	nameModule, err := sdk.NewIdentifier("name")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	newFn, err := sdk.NewIdentifier("new")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	lookupFn, err := sdk.NewIdentifier("lookup")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	optionModule, err := sdk.NewIdentifier("option")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	borrowFn, err := sdk.NewIdentifier("borrow")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	nameRecordModule, err := sdk.NewIdentifier("name_record")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	targetAddressFn, err := sdk.NewIdentifier("target_address")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}

	// Create type tags
	registryName, err := sdk.NewIdentifier("Registry")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	registryType := sdk.NewStructTag(iotaNamesPackageAddress, registryFn, registryName, []*sdk.TypeTag{})

	nameRecordName, err := sdk.NewIdentifier("NameRecord")
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	nameRecordType := sdk.NewStructTag(iotaNamesPackageAddress, nameRecordModule, nameRecordName, []*sdk.TypeTag{})

	// 1. Get the registry
	registryInput := builder.Input(sdk.UnresolvedInputNewShared(iotaNamesObjectId, 365644877, true))
	iotaNames := builder.MoveCall(
		sdk.Function{
			Package:  iotaNamesPackageAddress,
			Module:   iotaNamesModule,
			Function: registryFn,
			TypeArgs: []*sdk.TypeTag{sdk.TypeTagNewStruct(registryType)},
		},
		[]*sdk.Argument{registryInput},
	)

	// 2. Create name from string
	// BCS encode the string: length (as varint) + UTF-8 bytes
	nameBytes := []byte(name)
	nameLen := len(nameBytes)
	var bcsEncodedName []byte
	if nameLen < 128 {
		// For strings shorter than 128 bytes, length is encoded as single byte
		bcsEncodedName = append([]byte{byte(nameLen)}, nameBytes...)
	} else {
		// For longer strings, we'd need proper varint encoding
		// but for this example, the name should be short
		panic("String too long for simple BCS encoding")
	}
	nameInput := builder.Input(sdk.UnresolvedInputNewPure(bcsEncodedName))
	nameResult := builder.MoveCall(
		sdk.Function{
			Package:  iotaNamesPackageAddress,
			Module:   nameModule,
			Function: newFn,
			TypeArgs: []*sdk.TypeTag{},
		},
		[]*sdk.Argument{nameInput},
	)

	// 3. Lookup name record
	nameRecordOption := builder.MoveCall(
		sdk.Function{
			Package:  iotaNamesPackageAddress,
			Module:   registryFn,
			Function: lookupFn,
			TypeArgs: []*sdk.TypeTag{},
		},
		[]*sdk.Argument{iotaNames, nameResult},
	)

	// 4. Borrow name record from option
	nameRecord := builder.MoveCall(
		sdk.Function{
			Package:  stdlibAddress,
			Module:   optionModule,
			Function: borrowFn,
			TypeArgs: []*sdk.TypeTag{sdk.TypeTagNewStruct(nameRecordType)},
		},
		[]*sdk.Argument{nameRecordOption},
	)

	// 5. Get target address from name record
	targetAddressOption := builder.MoveCall(
		sdk.Function{
			Package:  iotaNamesPackageAddress,
			Module:   nameRecordModule,
			Function: targetAddressFn,
			TypeArgs: []*sdk.TypeTag{},
		},
		[]*sdk.Argument{nameRecord},
	)

	// 6. Borrow address from option
	builder.MoveCall(
		sdk.Function{
			Package:  stdlibAddress,
			Module:   optionModule,
			Function: borrowFn,
			TypeArgs: []*sdk.TypeTag{sdk.TypeTagNewAddress()},
		},
		[]*sdk.Argument{targetAddressOption},
	)

	builder.SetSender(senderAddress)
	builder.SetGasBudget(50000000)
	gasPrice, err := client.ReferenceGasPrice(nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	if gasPrice == nil {
		log.Fatalf("Missing reference gas price")
	}
	builder.SetGasPrice(*gasPrice)

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	skipChecks := true
	res, err := client.DryRunTx(txn, &skipChecks)
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
