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

	sender, _ := sdk.AddressFromHex("0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e")
	gas_coin_id, _ := sdk.ObjectIdFromHex("0xa1d009e8dafe20b1cba05e08aea488aafae1f89d892c3eaef6c0994e155e441a")

	builder := sdk.TransactionBuilderInit(sender, client)

	addr1, _ := sdk.AddressFromHex("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")
	addr2, _ := sdk.AddressFromHex("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")

	builder.MakeMoveVec([]*sdk.PtbArgument{sdk.PtbArgumentAddress(addr1), sdk.PtbArgumentAddress(addr2)}, sdk.TypeTagNewAddress(), "addresses")
	builder.MakeMoveVec([]*sdk.PtbArgument{sdk.PtbArgumentU64(10_000_000), sdk.PtbArgumentU64(20_000_000)}, sdk.TypeTagNewU64(), "amounts")

	package_id, _ := sdk.AddressFromHex("0x2")
	module_name, _ := sdk.NewIdentifier("vec_map")
	function_name, _ := sdk.NewIdentifier("from_keys_values")

	builder.MoveCall(
		package_id,
		module_name,
		function_name,
		[]*sdk.PtbArgument{sdk.PtbArgumentRes("addresses"), sdk.PtbArgumentRes("amounts")},
		[]*sdk.TypeTag{sdk.TypeTagNewAddress(), sdk.TypeTagNewU64()},
		nil,
	)

	builder.Gas(gas_coin_id).GasBudget(1000000000)

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to call generic Move function: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to call generic Move function: %v", *res.Error)
	}

	fmt.Print("Successfully called generic Move function")
}
