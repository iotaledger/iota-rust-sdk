// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"sort"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

const packageAddressHex = "0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f"

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	packageAddress, err := iota_sdk.AddressFromHex(packageAddressHex)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to parse package address: %v", err)
	}

	pkg, err := client.Package(packageAddress, nil)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to fetch package: %v", err)
	}
	if pkg == nil {
		log.Fatalf("Missing package: %s", packageAddressHex)
	}

	packageID := pkg.Id().ToHex()
	packageVersion := pkg.Version()

	fmt.Printf("Package ID: %s\n", packageID)
	fmt.Printf("Current version: %d\n\n", packageVersion)

	versionsPage, err := client.PackageVersions(packageAddress, nil, nil, nil)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to fetch package versions: %v", err)
	}

	versions := versionsPage.Data
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version() < versions[j].Version()
	})

	fmt.Println("Package versions:")
	for _, versionedPkg := range versions {
		marker := ""
		if versionedPkg.Id().ToHex() == packageID && versionedPkg.Version() == packageVersion {
			marker = " (current)"
		}
		fmt.Printf("- id=%s version=%d%s\n", versionedPkg.Id().ToHex(), versionedPkg.Version(), marker)
	}
	fmt.Println()

	fmt.Println("Dependencies:")
	dependencies := pkg.LinkageTable()
	if len(dependencies) == 0 {
		fmt.Println("- none")
	} else {
		for originalID, info := range dependencies {
			fmt.Printf("- %s -> %s (version %d)\n", originalID.ToHex(), info.UpgradedId.ToHex(), info.UpgradedVersion)
		}
	}
	fmt.Println()

	moduleIDs := pkg.Modules()
	moduleNames := make([]string, 0, len(moduleIDs))
	moduleIDByName := make(map[string]*iota_sdk.Identifier, len(moduleIDs))
	for moduleID := range moduleIDs {
		moduleName := moduleID.AsStr()
		moduleNames = append(moduleNames, moduleName)
		moduleIDByName[moduleName] = moduleID
	}
	sort.Strings(moduleNames)

	one := int32(1)
	for _, moduleName := range moduleNames {
		module, err := client.NormalizedMoveModule(
			packageAddress,
			moduleName,
			&packageVersion,
			nil,
			nil,
			nil,
			nil,
		)
		if err.(*iota_sdk.SdkFfiError) != nil {
			log.Fatalf("Failed to fetch module %s: %v", moduleName, err)
		}

		if module == nil {
			fmt.Printf("Module: %s (not found)\n", moduleName)
			continue
		}

		fmt.Printf("Module: %s\n", moduleName)
		fmt.Println("Functions:")
		if module.Functions == nil || len(module.Functions.Nodes) == 0 {
			fmt.Println("- none")
		} else {
			for _, fn := range module.Functions.Nodes {
				fmt.Printf("- %s\n", fn.String())
			}
		}

		fmt.Println("Types (with sample object if available):")
		if module.Structs == nil || len(module.Structs.Nodes) == 0 {
			fmt.Println("- none")
		} else {
			moduleID := moduleIDByName[moduleName]
			for _, structQuery := range module.Structs.Nodes {
				typeTag := fmt.Sprintf("%s::%s::%s", packageID, moduleID.AsStr(), structQuery.Name)
				objectPage, err := client.Objects(
					&iota_sdk.ObjectFilter{TypeTag: &typeTag},
					&iota_sdk.PaginationFilter{Direction: iota_sdk.DirectionForward, Limit: &one},
				)
				if err.(*iota_sdk.SdkFfiError) != nil {
					log.Fatalf("Failed to query objects for type %s: %v", typeTag, err)
				}
				if len(objectPage.Data) > 0 {
					fmt.Printf("- %s (example object: %s)\n", structQuery.Name, objectPage.Data[0].ObjectId().ToHex())
				} else {
					fmt.Printf("- %s (no example object found)\n", structQuery.Name)
				}
			}
		}

		fmt.Println()
	}
}
