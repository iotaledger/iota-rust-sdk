// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

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

	sender := addrFromHex("0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e")

	builder := client.TransactionBuilder(sender)

	addr1 := addrFromHex("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")
	addr2 := addrFromHex("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")

	package_id := iota_sdk.AddressFramework()
	module_name := identifier("vec_map")
	function_name := identifier("from_keys_values")

	builder.MoveCall(
		package_id,
		module_name,
		function_name,
		[]*iota_sdk.PtbArgument{
			iota_sdk.PtbArgumentAddressVec([]*iota_sdk.Address{addr1, addr2}),
			iota_sdk.PtbArgumentU64Vec([]uint64{10_000_000, 20_000_000}),
		},
		[]*iota_sdk.TypeTag{iota_sdk.TypeTagNewAddress(), iota_sdk.TypeTagNewU64()},
		nil,
	)

	res, err := builder.DryRun(false)
	if err != nil {
		log.Fatalf("Failed to call generic Move function: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to call generic Move function: %v", *res.Error)
	}

	fmt.Print("Successfully called generic Move function")
}
