// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"sort"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	packageAddress, err := iota_sdk.AddressFromHex("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	packageVersions, err := client.PackageVersions(packageAddress, nil, nil, nil)
	if err != nil {
		log.Fatalf("Failed to get package versions: %v", err)
	}
	if len(packageVersions.Data) == 0 {
		log.Fatalf("No package versions found")
	}

	versions := make([]uint64, 0, len(packageVersions.Data))
	for _, pkg := range packageVersions.Data {
		versions = append(versions, pkg.Version())
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	fmt.Printf("Versions: %v\n", versions)

	latestPackageOpt, err := client.PackageLatest(packageAddress)
	if err != nil {
		log.Fatalf("Failed to get latest package: %v", err)
	}
	if latestPackageOpt == nil {
		log.Fatalf("Latest package not found")
	}
	latestPackage := *latestPackageOpt

	fmt.Printf("Latest package id: %s\n", latestPackage.Id().ToHex())
	fmt.Printf("Latest package version: %d\n", latestPackage.Version())

	dependencies := latestPackage.LinkageTable()
	if len(dependencies) == 0 {
		fmt.Println("Dependencies: none")
	} else {
		fmt.Println("Dependencies:")
		for dependency := range dependencies {
			fmt.Printf("- %s\n", dependency.ToHex())
		}
	}

	latestVersion := latestPackage.Version()
	for moduleId := range latestPackage.Modules() {
		moduleOpt, err := client.NormalizedMoveModule(
			packageAddress,
			moduleId.AsStr(),
			&latestVersion,
			nil,
			nil,
			nil,
			nil,
		)
		if err != nil {
			log.Fatalf("Failed to get module: %v", err)
		}
		if moduleOpt == nil {
			continue
		}
		module := *moduleOpt

		fmt.Printf("\nModule: %s\n", moduleId.AsStr())
		if module.Functions != nil {
			fmt.Printf("Functions: %d\n", len(module.Functions.Nodes))
		}

		if module.Structs != nil {
			fmt.Printf("Structs: %d\n", len(module.Structs.Nodes))
			for i, moveStruct := range module.Structs.Nodes {
				if i >= 2 {
					break
				}
				structType := fmt.Sprintf("%s::%s::%s", latestPackage.Id().ToHex(), moduleId.AsStr(), moveStruct.Name)
				typedObjects, err := client.Objects(&iota_sdk.ObjectFilter{TypeTag: &structType}, nil)
				if err != nil {
					log.Fatalf("Failed to query objects by type: %v", err)
				}
				if len(typedObjects.Data) > 0 {
					fmt.Printf("- %s -> example object %s\n", moveStruct.Name, typedObjects.Data[0].ObjectId().ToHex())
				} else {
					fmt.Printf("- %s -> no objects found\n", moveStruct.Name)
				}
			}
		}
	}
}
