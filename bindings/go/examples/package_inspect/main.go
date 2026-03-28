// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func stringPtr(value string) *string {
	return &value
}

func forwardPage(cursor *string) *iota_sdk.PaginationFilter {
	return &iota_sdk.PaginationFilter{
		Direction: iota_sdk.DirectionForward,
		Cursor:    cursor,
	}
}

func fetchPackageVersions(client *iota_sdk.GraphQlClient, packageAddress *iota_sdk.Address) ([]*iota_sdk.MovePackage, error) {
	var versions []*iota_sdk.MovePackage
	var cursor *string

	for {
		page, err := client.PackageVersions(packageAddress, nil, nil, forwardPage(cursor))
		if err != nil {
			return nil, err
		}
		versions = append(versions, page.Data...)
		if page.PageInfo.HasNextPage {
			cursor = page.PageInfo.EndCursor
		} else {
			break
		}
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version() < versions[j].Version()
	})

	return versions, nil
}

func printObjectSamples(client *iota_sdk.GraphQlClient, typeTag string, isGeneric bool) {
	if isGeneric {
		fmt.Println("    sample objects: skipped for generic type")
		return
	}

	objects, err := client.Objects(
		&iota_sdk.ObjectFilter{TypeTag: stringPtr(typeTag)},
		forwardPage(nil),
	)
	if err != nil {
		log.Fatalf("Failed to fetch sample objects for %s: %v", typeTag, err)
	}

	if len(objects.Data) == 0 {
		fmt.Println("    sample objects: none found")
		return
	}

	fmt.Println("    sample objects:")
	for _, object := range objects.Data {
		fmt.Printf("      - %s (version %d)\n", object.ObjectId().ToHex(), object.Version())
	}
	if objects.PageInfo.HasNextPage {
		fmt.Println("      - ...")
	}
}

func main() {
	if len(os.Args) <= 1 {
		log.Fatalf("Usage: %s <PACKAGE_ID>", os.Args[0])
	}
	packageID := os.Args[1]

	packageAddress, err := iota_sdk.AddressFromHex(packageID)
	if err != nil {
		log.Fatalf("Failed to parse package id: %v", err)
	}

	client := iota_sdk.GraphQlClientNewTestnet()

	packageOpt, err := client.Package(packageAddress, nil)
	if err != nil {
		log.Fatalf("Failed to get package: %v", err)
	}
	if packageOpt == nil {
		log.Fatal("Missing package")
	}
	pkg := *packageOpt

	latestOpt, err := client.PackageLatest(packageAddress)
	if err != nil {
		log.Fatalf("Failed to get latest package: %v", err)
	}
	if latestOpt == nil {
		log.Fatal("Missing latest package")
	}
	latest := *latestOpt

	versions, err := fetchPackageVersions(client, packageAddress)
	if err != nil {
		log.Fatalf("Failed to get package versions: %v", err)
	}

	packagePrefix := pkg.Id().ToHex()

	fmt.Println("Requested package id:", packageID)
	fmt.Println("Resolved package id:", packagePrefix)
	fmt.Println("Resolved version:", pkg.Version())
	fmt.Printf("Latest version: %d (%s)\n", latest.Version(), latest.Id().ToHex())
	fmt.Println()

	fmt.Println("Versions:")
	for _, version := range versions {
		labels := []string{}
		if version.Id().Eq(pkg.Id()) {
			labels = append(labels, "requested")
		}
		if version.Id().Eq(latest.Id()) {
			labels = append(labels, "latest")
		}

		line := fmt.Sprintf("- v%d -> %s", version.Version(), version.Id().ToHex())
		if len(labels) > 0 {
			line += fmt.Sprintf(" [%s]", joinLabels(labels))
		}
		fmt.Println(line)
	}
	fmt.Println()

	fmt.Println("Dependencies:")
	linkageTable := pkg.LinkageTable()
	if len(linkageTable) == 0 {
		fmt.Println("- none")
	} else {
		originalIDs := make([]*iota_sdk.ObjectId, 0, len(linkageTable))
		for originalID := range linkageTable {
			originalIDs = append(originalIDs, originalID)
		}
		sort.Slice(originalIDs, func(i, j int) bool {
			return originalIDs[i].ToHex() < originalIDs[j].ToHex()
		})

		for _, originalID := range originalIDs {
			upgrade := linkageTable[originalID]
			fmt.Printf(
				"- %s -> %s @ v%d\n",
				originalID.ToHex(),
				upgrade.UpgradedId.ToHex(),
				upgrade.UpgradedVersion,
			)
		}
	}
	fmt.Println()

	fmt.Println("Modules, functions, and types:")
	moduleNames := make([]string, 0, len(pkg.Modules()))
	for moduleID := range pkg.Modules() {
		moduleNames = append(moduleNames, moduleID.AsStr())
	}
	sort.Strings(moduleNames)

	for _, moduleName := range moduleNames {
		fmt.Println("Module:", moduleName)

		module, err := client.NormalizedMoveModule(
			packageAddress,
			moduleName,
			nil,
			forwardPage(nil),
			forwardPage(nil),
			forwardPage(nil),
			forwardPage(nil),
		)
		if err != nil {
			log.Fatalf("Failed to get module metadata for %s: %v", moduleName, err)
		}
		if module == nil {
			fmt.Println("  metadata: missing")
			fmt.Println()
			continue
		}

		if module.Functions == nil || len(module.Functions.Nodes) == 0 {
			fmt.Println("  functions: none")
		} else {
			fmt.Println("  functions:")
			for _, function := range module.Functions.Nodes {
				fmt.Printf("    - %s\n", function.String())
			}
			if module.Functions.PageInfo.HasNextPage {
				fmt.Println("    - ...")
			}
		}

		if module.Structs == nil || len(module.Structs.Nodes) == 0 {
			fmt.Println("  types: none")
		} else {
			fmt.Println("  types:")
			for _, structType := range module.Structs.Nodes {
				typeTag := fmt.Sprintf("%s::%s::%s", packagePrefix, moduleName, structType.Name)
				fmt.Println("    -", typeTag)

				isGeneric := structType.TypeParameters != nil && len(*structType.TypeParameters) > 0
				printObjectSamples(client, typeTag, isGeneric)
			}
			if module.Structs.PageInfo.HasNextPage {
				fmt.Println("    - ...")
			}
		}

		fmt.Println()
	}
}

func joinLabels(labels []string) string {
	return strings.Join(labels, ", ")
}
