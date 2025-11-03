// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	sdk "bindings/iota_sdk_ffi"
	"fmt"
	"log"
)

func identifier(ident string) *sdk.Identifier {
	identifier, err := sdk.NewIdentifier(ident)
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}
	return identifier
}

func main() {
	client := sdk.GraphQlClientNewLocalnet()
	gasStationUrl := "http://0.0.0.0:9527"
	gasStationAuthToken := "test"
	keypair := sdk.Ed25519PrivateKeyGenerate()
	sender := keypair.PublicKey().DeriveAddress()
	simpleKey := sdk.SimpleKeypairFromEd25519(keypair)

	builder := sdk.ClientTransactionBuilderInit(sender, client)

	package_id := sdk.AddressStdLib()
	module_name := identifier("u64")
	function_name := identifier("sqrt")

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

	res, err := builder.Execute(simpleKey, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to sponsor transaction: %v", err)
	}

	if res != nil {
		log.Printf("%v", res)
	}

	fmt.Print("Sponsored transaction was successful!")
}
