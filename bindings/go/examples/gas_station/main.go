// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func identifier(ident string) *iota_sdk.Identifier {
	identifier, err := iota_sdk.NewIdentifier(ident)
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}
	return identifier
}

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()
	gasStationUrl := "http://0.0.0.0:9527"
	gasStationAuthToken := "test"
	keypair := iota_sdk.Ed25519PrivateKeyRandom()
	sender := keypair.PublicKey().DeriveAddress()
	signer := iota_sdk.TransactionSignerFromEd25519(keypair)

	builder := iota_sdk.NewTransactionBuilder(sender).WithClient(client)

	package_id := iota_sdk.AddressStd()
	module_name := identifier("u64")
	function_name := identifier("sqrt")

	builder.MoveCall(
		package_id,
		module_name,
		function_name,
		[]*iota_sdk.PtbArgument{iota_sdk.PtbArgumentU64(64)},
		nil,
		nil,
	)

	headers := make(map[string][]string)
	headers["Authorization"] = []string{fmt.Sprintf("Bearer %v", gasStationAuthToken)}

	builder.GasStationSponsor(gasStationUrl, nil, &headers)

	res, err := builder.Execute(signer, nil)
	if err != nil {
		log.Fatalf("Failed to sponsor transaction: %v", err)
	}

	if res != nil {
		log.Printf("%v", res)
	}

	fmt.Print("Sponsored transaction was successful!")
}
