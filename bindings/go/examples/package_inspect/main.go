// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example inspects a published Move package on testnet and prints its
// upgrade policy, version history, dependencies, functions, types, and sample
// objects.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

var frameworkPackageID = func() string {
	return iota_sdk.AddressFramework().ToHex()
}()

func main() {
	packageID := "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d"

	packageAddress, err := iota_sdk.AddressFromHex(packageID)
	if err != nil {
		log.Fatalf("Failed to parse package id: %v", err)
	}

	client := iota_sdk.GraphQlClientNewTestnet()

	// Fetch package metadata and version history.
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
		log.Fatal("missing latest package")
	}
	latest := *latestOpt

	versions, err := fetchPackageVersions(client, packageAddress)
	if err != nil {
		log.Fatalf("Failed to get package versions: %v", err)
	}

	packagePrefix := pkg.Id().ToHex()

	fmt.Printf("Latest version: %d (%s)\n", latest.Version().AsU64(), latest.Id().ToHex())
	// Resolve the current upgrade policy.
	currentPolicy, err := currentPackagePolicy(client, pkg.Id())
	if err != nil {
		log.Fatalf("Failed to get current package policy: %v", err)
	}
	fmt.Println("Current package policy:", currentPolicy)
	fmt.Println()

	// Print the package version history.
	fmt.Println("Versions:")
	for _, version := range versions {
		labels := []string{}
		if version.Id().Eq(pkg.Id()) {
			labels = append(labels, "requested")
		}
		if version.Id().Eq(latest.Id()) {
			labels = append(labels, "latest")
		}

		line := fmt.Sprintf("- v%d -> %s", version.Version().AsU64(), version.Id().ToHex())
		if len(labels) > 0 {
			line += fmt.Sprintf(" [%s]", joinLabels(labels))
		}
		fmt.Println(line)
	}
	fmt.Println()

	// Print package dependencies and their linked versions.
	fmt.Println("Dependencies:")
	linkageTable := pkg.LinkageTable()
	if len(linkageTable) == 0 {
		fmt.Println("- none")
	} else {
		upgrades := make([]iota_sdk.UpgradeInfo, 0, len(linkageTable))
		for _, upgrade := range linkageTable {
			upgrades = append(upgrades, upgrade)
		}
		sort.Slice(upgrades, func(i, j int) bool {
			return upgrades[i].UpgradedId.ToHex() < upgrades[j].UpgradedId.ToHex()
		})

		for _, upgrade := range upgrades {
			fmt.Printf(
				"- %s @ v%d\n",
				upgrade.UpgradedId.ToHex(),
				upgrade.UpgradedVersion.AsU64(),
			)
		}
	}
	fmt.Println()

	// Inspect normalized modules, functions, types, and sample key objects.
	fmt.Println("Package contents:")
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

type transactionEnvelopeJSON struct {
	V1 *transactionV1JSON `json:"1"`
}

type transactionV1JSON struct {
	Kind json.RawMessage `json:"kind"`
}

type programmableTransactionJSON struct {
	Kind     string            `json:"kind"`
	Inputs   []json.RawMessage `json:"inputs"`
	Commands []json.RawMessage `json:"commands"`
}

type commandJSON struct {
	Command   string            `json:"command"`
	Package   string            `json:"package"`
	Module    string            `json:"module"`
	Function  string            `json:"function"`
	Arguments []json.RawMessage `json:"arguments"`
}

type argumentJSON struct {
	Input  *uint16 `json:"input"`
	Result *uint16 `json:"result"`
}

type inputJSON struct {
	Type     string `json:"type"`
	ObjectID string `json:"object_id"`
}

func stringPtr(value string) *string {
	return &value
}

func forwardPage(cursor *string) *iota_sdk.PaginationFilter {
	return &iota_sdk.PaginationFilter{
		Direction: iota_sdk.DirectionForward,
		Cursor:    cursor,
	}
}

func shortenPackageIDs(signature string) string {
	var shortened strings.Builder
	shortened.Grow(len(signature))

	for index := 0; index < len(signature); {
		if signature[index] == '0' && index+1 < len(signature) && signature[index+1] == 'x' {
			end := index + 2
			for end < len(signature) {
				character := signature[end]
				if (character < '0' || character > '9') &&
					(character < 'a' || character > 'f') &&
					(character < 'A' || character > 'F') {
					break
				}
				end++
			}

			if end > index+2 {
				candidate := signature[index:end]
				if address, err := iota_sdk.AddressFromHex(candidate); err == nil {
					shortened.WriteString(address.ToShortHex())
				} else {
					shortened.WriteString(candidate)
				}
				index = end
				continue
			}
		}

		shortened.WriteByte(signature[index])
		index++
	}

	return shortened.String()
}

func formatFunctionSignature(signature string, packagePrefix string) string {
	return shortenPackageIDs(strings.ReplaceAll(signature, packagePrefix+"::", ""))
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
		return versions[i].Version().AsU64() < versions[j].Version().AsU64()
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
		fmt.Printf("      - %s (version %d)\n", object.Id().ToHex(), object.Version().AsU64())
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
		writtenVersion := effectsV1.LamportVersion()
		for _, changedObj := range effectsV1.ChangedObjects() {
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

func sameObjectID(left string, right string) bool {
	return strings.EqualFold(left, right)
}

func programmableTransactionFromTransaction(tx *iota_sdk.Transaction) (*programmableTransactionJSON, error) {
	jsonString, err := tx.ToJson()
	if err != nil {
		return nil, err
	}

	var envelope transactionEnvelopeJSON
	if err := json.Unmarshal([]byte(jsonString), &envelope); err != nil {
		return nil, err
	}
	if envelope.V1 == nil {
		return nil, nil
	}

	var programmableTx programmableTransactionJSON
	if err := json.Unmarshal(envelope.V1.Kind, &programmableTx); err != nil {
		return nil, err
	}
	if programmableTx.Kind != "programmable_transaction" {
		return nil, nil
	}

	return &programmableTx, nil
}

func isPackageMakeImmutableCall(command *commandJSON) bool {
	return command.Command == "move_call" &&
		sameObjectID(command.Package, frameworkPackageID) &&
		command.Module == "package" &&
		command.Function == "make_immutable"
}

func inputMatchesObjectID(rawInput json.RawMessage, objectID string) bool {
	var input inputJSON
	if err := json.Unmarshal(rawInput, &input); err != nil {
		return false
	}

	switch input.Type {
	case "immutable_or_owned", "receiving", "shared":
		return sameObjectID(input.ObjectID, objectID)
	default:
		return false
	}
}

func publishesPackageAsImmutable(tx *iota_sdk.Transaction) (bool, error) {
	programmableTx, err := programmableTransactionFromTransaction(tx)
	if err != nil || programmableTx == nil {
		return false, err
	}

	var publishIndexes []uint16
	for index, rawCommand := range programmableTx.Commands {
		var command commandJSON
		if err := json.Unmarshal(rawCommand, &command); err != nil {
			return false, err
		}
		if command.Command == "publish" {
			publishIndexes = append(publishIndexes, uint16(index))
		}
	}
	if len(publishIndexes) != 1 {
		return false, nil
	}

	publishIndex := publishIndexes[0]
	for _, rawCommand := range programmableTx.Commands[int(publishIndex)+1:] {
		var command commandJSON
		if err := json.Unmarshal(rawCommand, &command); err != nil {
			return false, err
		}
		if !isPackageMakeImmutableCall(&command) || len(command.Arguments) != 1 {
			continue
		}

		var argument argumentJSON
		if err := json.Unmarshal(command.Arguments[0], &argument); err != nil {
			continue
		}
		if argument.Result != nil && *argument.Result == publishIndex {
			return true, nil
		}
	}

	return false, nil
}

func usesUpgradeCapForMakeImmutable(tx *iota_sdk.Transaction, upgradeCapID *iota_sdk.ObjectId) (bool, error) {
	programmableTx, err := programmableTransactionFromTransaction(tx)
	if err != nil || programmableTx == nil {
		return false, err
	}

	var upgradeCapInputs []uint16
	for index, rawInput := range programmableTx.Inputs {
		if inputMatchesObjectID(rawInput, upgradeCapID.ToHex()) {
			upgradeCapInputs = append(upgradeCapInputs, uint16(index))
		}
	}
	if len(upgradeCapInputs) == 0 {
		return false, nil
	}

	for _, rawCommand := range programmableTx.Commands {
		var command commandJSON
		if err := json.Unmarshal(rawCommand, &command); err != nil {
			return false, err
		}
		if !isPackageMakeImmutableCall(&command) || len(command.Arguments) != 1 {
			continue
		}

		var argument argumentJSON
		if err := json.Unmarshal(command.Arguments[0], &argument); err != nil {
			continue
		}
		if argument.Input == nil {
			continue
		}

		for _, inputIndex := range upgradeCapInputs {
			if *argument.Input == inputIndex {
				return true, nil
			}
		}
	}

	return false, nil
}

func wasPackagePublishedAsImmutable(client *iota_sdk.GraphQlClient, packageID *iota_sdk.ObjectId) (bool, error) {
	var cursor *string

	for {
		page, err := client.TransactionsDataEffects(
			&iota_sdk.TransactionsFilter{ChangedObject: &packageID},
			forwardPage(cursor),
		)
		if err != nil {
			return false, err
		}

		for _, txData := range page.Data {
			madeImmutable, err := publishesPackageAsImmutable(txData.SignedTransaction.Transaction)
			if err != nil {
				return false, err
			}
			if madeImmutable {
				return true, nil
			}
		}

		if !page.PageInfo.HasNextPage {
			return false, nil
		}
		cursor = page.PageInfo.EndCursor
	}
}

func wasUpgradeCapUsedForMakeImmutable(client *iota_sdk.GraphQlClient, upgradeCapID *iota_sdk.ObjectId) (bool, error) {
	var cursor *string

	for {
		page, err := client.TransactionsDataEffects(
			&iota_sdk.TransactionsFilter{InputObject: &upgradeCapID},
			forwardPage(cursor),
		)
		if err != nil {
			return false, err
		}

		for _, txData := range page.Data {
			madeImmutable, err := usesUpgradeCapForMakeImmutable(txData.SignedTransaction.Transaction, upgradeCapID)
			if err != nil {
				return false, err
			}
			if madeImmutable {
				return true, nil
			}
		}

		if !page.PageInfo.HasNextPage {
			return false, nil
		}
		cursor = page.PageInfo.EndCursor
	}
}

func currentPackagePolicy(client *iota_sdk.GraphQlClient, packageID *iota_sdk.ObjectId) (string, error) {
	upgradeCapID, err := resolveUpgradeCapID(client, packageID)
	if err != nil {
		return "", err
	}
	if upgradeCapID == nil {
		if immutable, err := wasPackagePublishedAsImmutable(client, packageID); err != nil {
			return "", err
		} else if immutable {
			return "Immutable", nil
		}
		return "Unavailable", nil
	}

	contents, err := client.MoveObjectContents(upgradeCapID, nil)
	if err != nil {
		return "", err
	}
	if contents == nil {
		if immutable, err := wasUpgradeCapUsedForMakeImmutable(client, upgradeCapID); err != nil {
			return "", err
		} else if immutable {
			return "Immutable", nil
		}
		return "Unavailable", nil
	}

	if policy, ok := extractPolicy(*contents); ok {
		return formatPolicyName(policy), nil
	}

	return "Unavailable", nil
}
