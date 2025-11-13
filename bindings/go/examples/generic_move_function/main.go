// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk"
)

func addrFromHex(hex string) *sdk.Address {
	address, err := sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func identifier(ident string) *sdk.Identifier {
	identifier, err := sdk.NewIdentifier(ident)
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}
	return identifier
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender := addrFromHex("0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e")

	builder := sdk.NewTransactionBuilder(sender).WithClient(client)

	addr1 := addrFromHex("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")
	addr2 := addrFromHex("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")

	package_id := sdk.AddressFramework()
	module_name := identifier("vec_map")
	function_name := identifier("from_keys_values")

	builder.MoveCall(
		package_id,
		module_name,
		function_name,
		[]*sdk.PtbArgument{
			sdk.PtbArgumentAddressVec([]*sdk.Address{addr1, addr2}),
			sdk.PtbArgumentU64Vec([]uint64{10_000_000, 20_000_000}),
		},
		[]*sdk.TypeTag{sdk.TypeTagNewAddress(), sdk.TypeTagNewU64()},
		nil,
	)

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to call generic Move function: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to call generic Move function: %v", *res.Error)
	}

	fmt.Print("Successfully called generic Move function")
}
