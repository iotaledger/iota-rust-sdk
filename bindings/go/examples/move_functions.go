// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	sdk "bindings/iota_sdk_ffi"
	"fmt"
	"log"
)

func isNilError(err error) bool {
	if sdkErr, ok := err.(*sdk.SdkFfiError); ok {
		return sdkErr == nil
	}
	return false
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	packageAddress, err := sdk.AddressFromHex("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	
	packageOpt, err := client.Package(packageAddress, nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get package: %v", err)
	}
	if packageOpt == nil {
		log.Fatalf("Missing package: %v", err)
	}
	pkg := *packageOpt

	for moduleId, _ := range pkg.Modules() {
		moduleOpt, err := client.NormalizedMoveModule(
			packageAddress,
			moduleId.AsStr(),
			nil,
			nil,
			nil,
			nil,
			nil,
		)
		if !isNilError(err) {
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
