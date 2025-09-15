// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"fmt"
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	sender, _ := sdk.AddressFromHex("0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e")
	gas_coin_id, _ := sdk.ObjectIdFromHex("0xa1d009e8dafe20b1cba05e08aea488aafae1f89d892c3eaef6c0994e155e441a")

	gas_coin_obj, err := client.Object(gas_coin_id, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to fetch gas coin object: %v", err)
	}
	gas_coin := sdk.UnresolvedInputFromObject(*gas_coin_obj).WithOwnedKind()

	reference_gas_price, err := client.ReferenceGasPrice(nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to fetch reference gas price: %v", err)
	}

	builder := sdk.NewTransactionBuilder()

	addr1, _ := sdk.AddressFromHex("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")
	addr2, _ := sdk.AddressFromHex("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")

	addr1_arg := builder.Input(sdk.UnresolvedInputNewPure(addr1.ToBytes()))
	addr2_arg := builder.Input(sdk.UnresolvedInputNewPure(addr2.ToBytes()))

	address_type_tag := sdk.TypeTagNewAddress()
	balance_type_tag := sdk.TypeTagNewU64()

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, 10_000_000)
	bal1_arg := builder.Input(sdk.UnresolvedInputNewPure(buf))
	binary.LittleEndian.PutUint64(buf, 20_000_000)
	bal2_arg := builder.Input(sdk.UnresolvedInputNewPure(buf))

	arg1 := builder.MakeMoveVec(&address_type_tag, []*sdk.Argument{addr1_arg, addr2_arg})
	arg2 := builder.MakeMoveVec(&balance_type_tag, []*sdk.Argument{bal1_arg, bal2_arg})

	package_name, _ := sdk.AddressFromHex("0x2")
	module_name, _ := sdk.NewIdentifier("vec_map")
	function_name, _ := sdk.NewIdentifier("from_keys_values")

	function := sdk.Function{Package: package_name,
		Module:   module_name,
		Function: function_name,
		TypeArgs: []*sdk.TypeTag{address_type_tag, balance_type_tag},
	}

	builder.MoveCall(function, []*sdk.Argument{arg1, arg2})

	builder.SetGasBudget(50_000_000)
	builder.SetGasPrice(*reference_gas_price)
	builder.SetSender(sender)
	builder.AddGasObjects([]*sdk.UnresolvedInput{gas_coin})

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	skipChecks := false
	res, err := client.DryRunTx(txn, &skipChecks)

	if res.Error != nil {
		log.Fatalf("Failed to call generic Move function: %v", err)
	}

	fmt.Print("Successfully called generic Move function")
}
