// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	sdk "bindings/iota_sdk_ffi"
	"fmt"
	"log"
)

func main() {
	client := sdk.GraphQlClientNewLocalnet()
	gasStationUrl := "http://0.0.0.0:9527"
	gasStationAuthToken := "test"
	keypair := sdk.Ed25519PrivateKeyGenerate()
	sender := keypair.PublicKey().DeriveAddress()
	simpleKey := sdk.SimpleKeypairFromEd25519(keypair)

	builder := sdk.TransactionBuilderInit(sender, client)

	package_id, _ := sdk.AddressFromHex("0x1")
	module_name, _ := sdk.NewIdentifier("u64")
	function_name, _ := sdk.NewIdentifier("sqrt")

	builder.MoveCall(
		package_id,
		module_name,
		function_name,
		[]*sdk.PtbArgument{sdk.PtbArgumentU64(64)},
		nil,
		nil,
	)

	headers := make(map[string][]string)
	headers["Authorization"] = []string{fmt.Sprintf("Bearer %v", gasStationAuthToken)}

	builder.GasStationSponsor(gasStationUrl, nil, &headers)

	res, err := builder.Execute(simpleKey, true)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to sponsor transaction: %v", err)
	}

	if res != nil {
		log.Printf("%v", *res)
	}

	fmt.Print("Sponsored transaction was successful!")
}
