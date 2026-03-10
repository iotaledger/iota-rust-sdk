// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	packageAddress, err := iota_sdk.AddressFromHex("0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

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
