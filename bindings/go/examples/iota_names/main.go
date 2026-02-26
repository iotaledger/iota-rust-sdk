// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example demonstrates the major IOTA Names operations:
//
// 1. Name lookup: resolve an IOTA name to an address
// 2. Reverse lookup: resolve an address back to its IOTA name
// 3. Name record details: query expiration timestamp
// 4. Check existence: verify if a name is registered
//
// All operations use dev_inspect (dry run) so no gas or signing is needed.

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

// IOTA Names configuration per network
type iotaNamesConfig struct {
	packageHex string
	objectHex  string
}

var configs = map[string]iotaNamesConfig{
	"devnet": {
		packageHex: "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba",
		objectHex:  "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342",
	},
	"mainnet": {
		packageHex: "0x6d2c743607ef275bd6934fe5c2a7e5179cca6fbd2049cfa79de2310b74f3cf83",
		objectHex:  "0xa14e5d0481a7aa346157078e6facba3cd895d97038cd87b9f2cc24b0c6102d75",
	},
}

// Active config (set in main based on CLI args)
var iotaNamesPackageHex = configs["devnet"].packageHex
var iotaNamesObjectHex = configs["devnet"].objectHex

func mustAddr(hex string) *iota_sdk.Address {
	addr, err := iota_sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return addr
}

func mustObjId(hex string) *iota_sdk.ObjectId {
	id, err := iota_sdk.ObjectIdFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	return id
}

func ident(s string) *iota_sdk.Identifier {
	id, err := iota_sdk.NewIdentifier(s)
	if err != nil {
		log.Fatalf("Failed to create identifier: %v", err)
	}
	return id
}

func registryTypeTag(pkg *iota_sdk.Address) *iota_sdk.TypeTag {
	return iota_sdk.TypeTagNewStruct(
		iota_sdk.NewStructTag(pkg, ident("registry"), ident("Registry"), []*iota_sdk.TypeTag{}),
	)
}

func nameRecordTypeTag(pkg *iota_sdk.Address) *iota_sdk.TypeTag {
	return iota_sdk.TypeTagNewStruct(
		iota_sdk.NewStructTag(pkg, ident("name_record"), ident("NameRecord"), []*iota_sdk.TypeTag{}),
	)
}

// Example 1: Look up an IOTA name to get the associated address.
func lookupName(client *iota_sdk.GraphQlClient, name string) *iota_sdk.Address {
	pkg := mustAddr(iotaNamesPackageHex)
	obj := mustObjId(iotaNamesObjectHex)
	std := iota_sdk.AddressStd()
	sender := iota_sdk.AddressZero()

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)

	// 1. Get the registry
	builder.MoveCall(
		pkg, ident("iota_names"), ident("registry"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentSharedMut(obj)},
		[]*iota_sdk.TypeTag{registryTypeTag(pkg)},
		[]string{"iota_names"},
	)

	// 2. Create name from string
	builder.MoveCall(
		pkg, ident("name"), ident("new"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentString(name)},
		nil,
		[]string{"name"},
	)

	// 3. Lookup name record
	builder.MoveCall(
		pkg, ident("registry"), ident("lookup"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("iota_names"), iota_sdk.PtbArgumentAssigned("name")},
		nil,
		[]string{"name_record_opt"},
	)

	// 4. Borrow name record from option
	builder.MoveCall(
		std, ident("option"), ident("borrow"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("name_record_opt")},
		[]*iota_sdk.TypeTag{nameRecordTypeTag(pkg)},
		[]string{"name_record"},
	)

	// 5. Get target address from name record
	builder.MoveCall(
		pkg, ident("name_record"), ident("target_address"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("name_record")},
		nil,
		[]string{"target_address_opt"},
	)

	// 6. Borrow address from option
	builder.MoveCall(
		std, ident("option"), ident("borrow"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("target_address_opt")},
		[]*iota_sdk.TypeTag{iota_sdk.TypeTagNewAddress()},
		[]string{"target_address"},
	)

	res, err := builder.DryRun(true)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to dry run: %v", err)
	}

	if res.Error != nil {
		// Name not found or expired
		return nil
	}

	if len(res.Results) > 0 {
		lastEffect := res.Results[len(res.Results)-1]
		if len(lastEffect.ReturnValues) > 0 {
			rv := lastEffect.ReturnValues[0]
			if rv.TypeTag.IsAddress() && len(rv.Bcs) == 32 {
				addr, err := iota_sdk.AddressFromBytes(rv.Bcs)
				if err != nil {
					return nil
				}
				return addr
			}
		}
	}
	return nil
}

// Example 2: Reverse lookup - resolve an address to its IOTA name.
func reverseLookup(client *iota_sdk.GraphQlClient, address *iota_sdk.Address) {
	pkg := mustAddr(iotaNamesPackageHex)
	obj := mustObjId(iotaNamesObjectHex)
	sender := iota_sdk.AddressZero()

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)

	// Get the shared registry
	builder.MoveCall(
		pkg, ident("iota_names"), ident("registry"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentSharedMut(obj)},
		[]*iota_sdk.TypeTag{registryTypeTag(pkg)},
		[]string{"registry"},
	)

	// Reverse lookup: address -> Option<Name>
	builder.MoveCall(
		pkg, ident("registry"), ident("reverse_lookup"),
		[]*iota_sdk.PtbArgument{
			iota_sdk.PtbArgumentAssigned("registry"),
			iota_sdk.PtbArgumentAddress(address),
		},
		nil,
		[]string{"name_opt"},
	)

	res, err := builder.DryRun(true)
	if err.(*iota_sdk.SdkFfiError) != nil {
		fmt.Printf("  Reverse lookup failed: %v\n", err)
		return
	}

	if res.Error != nil {
		fmt.Printf("  Reverse lookup failed: %v\n", *res.Error)
		return
	}

	if len(res.Results) > 0 {
		lastEffect := res.Results[len(res.Results)-1]
		if len(lastEffect.ReturnValues) > 0 {
			rv := lastEffect.ReturnValues[0]
			if len(rv.Bcs) > 0 && rv.Bcs[0] == 1 {
				fmt.Printf("  Address %s has a reverse name record\n", address.ToHex())
			} else {
				fmt.Printf("  Address %s does not have a reverse name record\n", address.ToHex())
			}
		}
	}
}

// Example 3: Query name record details (target address, expiration).
func nameRecordDetails(client *iota_sdk.GraphQlClient, name string) {
	// First check if the name exists to avoid option::borrow abort
	if !checkNameExists(client, name) {
		fmt.Printf("  Name '%s' is not registered, no record to query.\n", name)
		return
	}

	pkg := mustAddr(iotaNamesPackageHex)
	obj := mustObjId(iotaNamesObjectHex)
	std := iota_sdk.AddressStd()
	sender := iota_sdk.AddressZero()

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)

	// Get the shared registry
	builder.MoveCall(
		pkg, ident("iota_names"), ident("registry"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentSharedMut(obj)},
		[]*iota_sdk.TypeTag{registryTypeTag(pkg)},
		[]string{"registry"},
	)

	// Create the name object
	builder.MoveCall(
		pkg, ident("name"), ident("new"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentString(name)},
		nil,
		[]string{"name"},
	)

	// Look up the name record
	builder.MoveCall(
		pkg, ident("registry"), ident("lookup"),
		[]*iota_sdk.PtbArgument{
			iota_sdk.PtbArgumentAssigned("registry"),
			iota_sdk.PtbArgumentAssigned("name"),
		},
		nil,
		[]string{"name_record_opt"},
	)

	// Borrow the name record from Option
	builder.MoveCall(
		std, ident("option"), ident("borrow"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("name_record_opt")},
		[]*iota_sdk.TypeTag{nameRecordTypeTag(pkg)},
		[]string{"name_record"},
	)

	// Get the target address
	builder.MoveCall(
		pkg, ident("name_record"), ident("target_address"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("name_record")},
		nil,
		[]string{"target_address_opt"},
	)

	// Get the expiration timestamp
	builder.MoveCall(
		pkg, ident("name_record"), ident("expiration_timestamp_ms"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentAssigned("name_record")},
		nil,
		[]string{"expiration"},
	)

	res, err := builder.DryRun(true)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to dry run: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Name record query failed: %v", *res.Error)
	}

	fmt.Printf("  Name record details for '%s':\n", name)

	// Extract expiration (u64)
	for _, effect := range res.Results {
		for _, rv := range effect.ReturnValues {
			if rv.TypeTag.IsU64() && len(rv.Bcs) == 8 {
				timestamp := binary.LittleEndian.Uint64(rv.Bcs)
				fmt.Printf("  Expiration timestamp (ms): %d\n", timestamp)
			}
		}
	}

	// Extract target address from Option<address> (5th move call, index 4)
	if len(res.Results) > 4 {
		effect := res.Results[4]
		if len(effect.ReturnValues) > 0 {
			rv := effect.ReturnValues[0]
			if len(rv.Bcs) == 33 && rv.Bcs[0] == 1 {
				addr, err := iota_sdk.AddressFromBytes(rv.Bcs[1:33])
				if err == nil {
					fmt.Printf("  Target address: %s\n", addr.ToHex())
				}
			} else {
				fmt.Println("  Target address: not set")
			}
		}
	}
}

// Example 4: Check if a name exists in the registry.
func checkNameExists(client *iota_sdk.GraphQlClient, name string) bool {
	pkg := mustAddr(iotaNamesPackageHex)
	obj := mustObjId(iotaNamesObjectHex)
	sender := iota_sdk.AddressZero()

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)

	// Get the shared registry
	builder.MoveCall(
		pkg, ident("iota_names"), ident("registry"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentSharedMut(obj)},
		[]*iota_sdk.TypeTag{registryTypeTag(pkg)},
		[]string{"registry"},
	)

	// Create the name object
	builder.MoveCall(
		pkg, ident("name"), ident("new"),
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentString(name)},
		nil,
		[]string{"name"},
	)

	// Check if the name has a record
	builder.MoveCall(
		pkg, ident("registry"), ident("has_record"),
		[]*iota_sdk.PtbArgument{
			iota_sdk.PtbArgumentAssigned("registry"),
			iota_sdk.PtbArgumentAssigned("name"),
		},
		nil,
		[]string{"exists"},
	)

	res, err := builder.DryRun(true)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to dry run: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("has_record check failed: %v", *res.Error)
	}

	if len(res.Results) > 0 {
		lastEffect := res.Results[len(res.Results)-1]
		if len(lastEffect.ReturnValues) > 0 {
			rv := lastEffect.ReturnValues[0]
			if rv.TypeTag.IsBool() && len(rv.Bcs) > 0 {
				return rv.Bcs[0] == 1
			}
		}
	}
	return false
}

func main() {
	name := "name.iota"
	network := "devnet"

	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	if len(os.Args) > 2 {
		network = os.Args[2]
	}

	if cfg, ok := configs[network]; ok {
		iotaNamesPackageHex = cfg.packageHex
		iotaNamesObjectHex = cfg.objectHex
	}

	var client *iota_sdk.GraphQlClient
	if network == "mainnet" {
		client = iota_sdk.GraphQlClientNewMainnet()
	} else {
		client = iota_sdk.GraphQlClientNewDevnet()
	}

	fmt.Printf("=== IOTA Names Examples (%s) ===\n", network)
	fmt.Println()

	// Example 1: Name lookup (name -> address)
	fmt.Printf("1. Looking up '%s'...\n", name)
	address := lookupName(client, name)
	if address != nil {
		fmt.Printf("   Resolved to: %s\n\n", address.ToHex())

		// Example 2: Reverse lookup (address -> name)
		fmt.Printf("2. Reverse lookup for %s...\n", address.ToHex())
		reverseLookup(client, address)
		fmt.Println()
	} else {
		fmt.Println("   Name not found or expired")
		fmt.Println()
		fmt.Println("2. Skipping reverse lookup (no address to look up)")
		fmt.Println()
	}

	// Example 3: Name record details
	fmt.Printf("3. Querying name record details for '%s'...\n", name)
	nameRecordDetails(client, name)
	fmt.Println()

	// Example 4: Check if names exist
	fmt.Println("4. Checking name existence...")
	exists := checkNameExists(client, name)
	fmt.Printf("   '%s' exists: %v\n", name, exists)

	fakeName := "this-name-probably-does-not-exist-12345.iota"
	fakeExists := checkNameExists(client, fakeName)
	fmt.Printf("   '%s' exists: %v\n", fakeName, fakeExists)
}
