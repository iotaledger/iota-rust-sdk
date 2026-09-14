// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// The same demo as on develop, against the map-object API: lookups now hit.
// Offline: the package is built locally, no node is involved.

package main

import (
	"fmt"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	id, err := iota_sdk.ObjectIdFromHex(
		"0x0000000000000000000000000000000000000000000000000000000000000002",
	)
	if err != nil {
		panic(err)
	}
	coin, err := iota_sdk.NewIdentifier("coin")
	if err != nil {
		panic(err)
	}

	// Building the package now goes through the map objects.
	modules := iota_sdk.NewPackageModules([]iota_sdk.ModuleEntry{
		{Key: coin, Value: []byte{0xde, 0xad, 0xbe, 0xef}},
	})
	pkg, err := iota_sdk.NewMovePackage(
		id,
		iota_sdk.VersionFromU64(1),
		modules,
		nil,
		iota_sdk.NewLinkageTable(nil),
	)
	if err != nil {
		panic(err)
	}

	returned := pkg.Modules()

	fmt.Printf("modules returned: %d\n", returned.Len())
	for _, entry := range returned.Entries() {
		fmt.Printf("  iterated: %q -> %x\n", entry.Key.AsStr(), entry.Value)
	}

	fmt.Printf("\nlookup with the key we passed in:      %v\n", returned.Get(coin) != nil)

	same, err := iota_sdk.NewIdentifier("coin")
	if err != nil {
		panic(err)
	}
	fmt.Printf("lookup with an equal key:              %v\n", returned.Get(same) != nil)

	fmt.Printf("key from one call, looked up in next:  %v\n",
		pkg.Modules().ContainsKey(returned.Keys()[0]))

	fmt.Println("\nLookup runs in Rust against the key's Eq/Hash, so it works everywhere.")
}
