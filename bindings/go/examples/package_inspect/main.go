// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
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

func formatFunctionSignature(signature string, packagePrefix string) string {
	return strings.ReplaceAll(signature, packagePrefix+"::", "")
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

func printObjectSamples(client *iota_sdk.GraphQlClient, typeTag string, hasKeyAbility bool, isGeneric bool) {
	if !hasKeyAbility {
		return
	}

	if isGeneric {
		fmt.Println("    sample objects: skipped for generic type")
		return
	}

	limit := int32(3)
	objects, err := client.Objects(
		&iota_sdk.ObjectFilter{TypeTag: stringPtr(typeTag)},
		&iota_sdk.PaginationFilter{
			Direction: iota_sdk.DirectionForward,
			Limit:     &limit,
		},
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

func formatPolicyName(policy uint8) string {
	switch policy {
	case 0:
		return "Compatible"
	case 128:
		return "Additive"
	case 192:
		return "Dependency-only"
	default:
		return fmt.Sprintf("Unknown (%d)", policy)
	}
}

func extractPolicy(contents string) (uint8, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(contents), &raw); err != nil {
		return 0, false
	}

	policyRaw, ok := raw["policy"]
	if !ok {
		return 0, false
	}

	var number uint8
	if err := json.Unmarshal(policyRaw, &number); err == nil {
		return number, true
	}

	var text string
	if err := json.Unmarshal(policyRaw, &text); err == nil {
		parsed, err := strconv.ParseUint(text, 10, 8)
		if err == nil {
			return uint8(parsed), true
		}
	}

	return 0, false
}

func resolveUpgradeCapID(client *iota_sdk.GraphQlClient, packageID *iota_sdk.ObjectId) (*iota_sdk.ObjectId, error) {
	limit := int32(1)
	page, err := client.TransactionsEffects(
		&iota_sdk.TransactionsFilter{ChangedObject: &packageID},
		&iota_sdk.PaginationFilter{Direction: iota_sdk.DirectionForward, Limit: &limit},
	)
	if err != nil {
		return nil, err
	}

	for _, effects := range page.Data {
		effectsV1 := effects.AsV1()
		writtenVersion := effectsV1.LamportVersion
		for _, changedObj := range effectsV1.ChangedObjects {
			if _, ok := changedObj.OutputState.(iota_sdk.ObjectOutObjectWrite); !ok {
				continue
			}

			objPtr, err := client.Object(changedObj.ObjectId, &writtenVersion)
			if err != nil {
				return nil, err
			}

			if objPtr == nil {
				continue
			}

			obj := *objPtr
			if obj.AsStructOpt() != nil {
				upgradeCapType := iota_sdk.StructTagNewUpgradeCap()
				if obj.AsStruct().StructType.Eq(upgradeCapType) {
					return changedObj.ObjectId, nil
				}
			}
		}
	}

	return nil, nil
}

func currentPackagePolicy(client *iota_sdk.GraphQlClient, packageID *iota_sdk.ObjectId) (string, error) {
	upgradeCapID, err := resolveUpgradeCapID(client, packageID)
	if err != nil {
		return "", err
	}
	if upgradeCapID == nil {
		return "Unavailable", nil
	}

	contents, err := client.MoveObjectContents(upgradeCapID, nil)
	if err != nil {
		return "", err
	}
	if contents == nil {
		return "Unavailable", nil
	}

	if policy, ok := extractPolicy(*contents); ok {
		return formatPolicyName(policy), nil
	}

	return "Unavailable", nil
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
	currentPolicy, err := currentPackagePolicy(client, pkg.Id())
	if err != nil {
		log.Fatalf("Failed to get current package policy: %v", err)
	}
	fmt.Println("Current package policy:", currentPolicy)
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
				fmt.Printf("    - %s\n", formatFunctionSignature(function.String(), packagePrefix))
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

				hasKeyAbility := false
				if structType.Abilities != nil {
					for _, ability := range *structType.Abilities {
						if ability == iota_sdk.MoveAbilityKey {
							hasKeyAbility = true
							break
						}
					}
				}
				isGeneric := structType.TypeParameters != nil && len(*structType.TypeParameters) > 0
				printObjectSamples(client, typeTag, hasKeyAbility, isGeneric)
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
