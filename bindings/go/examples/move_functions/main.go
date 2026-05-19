// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	// Inspect the IOTA framework package (0x2). It is present on every network
	// including localnet.
	packageAddress := iota_sdk.AddressFramework()

	packageOpt, err := client.Package(packageAddress, nil)
	if err != nil {
		log.Fatalf("Failed to get package: %v", err)
	}
	if packageOpt == nil {
		log.Fatalf("Missing package: %v", err)
	}
	pkg := *packageOpt

	for moduleId := range pkg.Modules() {
		moduleOpt, err := client.NormalizedMoveModule(
			packageAddress,
			moduleId.AsStr(),
			nil,
			nil,
			nil,
			nil,
			nil,
		)
		if err != nil {
			log.Fatalf("Failed to get module: %v", err)
		}
		if moduleOpt == nil {
			log.Fatalf("Module: %v not found", moduleId.AsStr())
		}
		module := *moduleOpt
		if module.Functions != nil {
			fmt.Println("Module:", moduleId.AsStr())
			for _, fun := range module.Functions.Nodes {
				fmt.Println("- ", fun.String())
			}
			fmt.Println()
		}
	}
}
