// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example inspects a published Move package on testnet and prints its
// upgrade policy, version history, dependencies, functions, types, and sample
// objects.

import Foundation
import IotaSDK

private let frameworkPackageId = Address.framework().toHex()

@main
struct PackageInspectExample {
  static func main() async throws {
    let packageId = "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d"

    let packageAddress = try Address.fromHex(hex: packageId)
    let client = GraphQlClient.newTestnet()

    // Fetch package metadata and version history.
    guard let package = try await client.package(address: packageAddress) else {
      throw NSError(
        domain: "PackageInspect", code: 2,
        userInfo: [NSLocalizedDescriptionKey: "missing package"])
    }
    guard let latestPackage = try await client.packageLatest(address: packageAddress) else {
      throw NSError(
        domain: "PackageInspect", code: 3,
        userInfo: [NSLocalizedDescriptionKey: "missing latest package"])
    }

    let versions = try await fetchPackageVersions(client: client, packageAddress: packageAddress)
    let packagePrefix = package.id().toHex()
    print("Latest version: \(latestPackage.version().asU64()) (\(latestPackage.id().toHex()))")
    // Resolve the current upgrade policy.
    let currentPolicy = try await currentPackagePolicy(client: client, packageId: package.id())
    print("Current package policy: \(currentPolicy)")
    print()

    // Print the package version history.
    print("Versions:")
    for version in versions {
      var labels: [String] = []
      if version.id() == package.id() {
        labels.append("requested")
      }
      if version.id() == latestPackage.id() {
        labels.append("latest")
      }

      let suffix = labels.isEmpty ? "" : " [\(labels.joined(separator: ", "))]"
      print("- v\(version.version().asU64()) -> \(version.id().toHex())\(suffix)")
    }
    print()

    // Print package dependencies and their linked versions.
    print("Dependencies:")
    let dependencies = package.linkageTable().values.sorted {
      $0.upgradedId.toHex() < $1.upgradedId.toHex()
    }
    if dependencies.isEmpty {
      print("- none")
    } else {
      for upgrade in dependencies {
        print("- \(upgrade.upgradedId.toHex()) @ v\(upgrade.upgradedVersion.asU64())")
      }
    }
    print()

    // Inspect normalized modules, functions, types, and sample key objects.
    print("Package contents:")
    let moduleNames = package.modules().keys.map { $0.asStr() }.sorted()
    for moduleName in moduleNames {
      print("Module: \(moduleName)")

      let module = try await client.normalizedMoveModule(
        package: packageAddress,
        module: moduleName,
        version: nil,
        paginationFilterEnums: forwardPage(),
        paginationFilterFriends: forwardPage(),
        paginationFilterFunctions: forwardPage(),
        paginationFilterStructs: forwardPage()
      )

      guard let module else {
        print("  metadata: missing")
        print()
        continue
      }

      if let functions = module.functions, !functions.nodes.isEmpty {
        print("  functions:")
        for function in functions.nodes {
          let signature = formatFunctionSignature(
            String(describing: function),
            packagePrefix: packagePrefix
          )
          print("    - \(signature)")
        }
        if functions.pageInfo.hasNextPage {
          print("    - ...")
        }
      } else {
        print("  functions: none")
      }

      if let structs = module.structs, !structs.nodes.isEmpty {
        print("  types:")
        for structType in structs.nodes {
          let typeTag = "\(packagePrefix)::\(moduleName)::\(structType.name)"
          print("    - \(typeTag)")
          let hasKeyAbility = (structType.abilities ?? []).contains(.key)
          let isGeneric = !(structType.typeParameters ?? []).isEmpty
          try await printObjectSamples(
            client: client,
            typeTag: typeTag,
            hasKeyAbility: hasKeyAbility,
            isGeneric: isGeneric
          )
        }
        if structs.pageInfo.hasNextPage {
          print("    - ...")
        }
      } else {
        print("  types: none")
      }

      print()
    }
  }
}

private func forwardPage(cursor: String? = nil) -> PaginationFilter {
  PaginationFilter(direction: .forward, cursor: cursor)
}

private func isHexDigit(_ character: Character) -> Bool {
  character.unicodeScalars.allSatisfy { scalar in
    switch scalar.value {
    case 48...57, 65...70, 97...102:
      return true
    default:
      return false
    }
  }
}

private func shortenPackageIds(_ signature: String) -> String {
  var shortened = ""
  shortened.reserveCapacity(signature.count)

  var index = signature.startIndex
  while index < signature.endIndex {
    let nextIndex = signature.index(after: index)
    if signature[index] == "0", nextIndex < signature.endIndex, signature[nextIndex] == "x" {
      var end = signature.index(after: nextIndex)
      while end < signature.endIndex, isHexDigit(signature[end]) {
        end = signature.index(after: end)
      }

      if end > signature.index(after: nextIndex) {
        let candidate = String(signature[index..<end])
        if let address = try? Address.fromHex(hex: candidate) {
          shortened += address.toShortHex()
        } else {
          shortened += candidate
        }
        index = end
        continue
      }
    }

    shortened.append(signature[index])
    index = nextIndex
  }

  return shortened
}

private func formatFunctionSignature(_ signature: String, packagePrefix: String) -> String {
  shortenPackageIds(signature.replacingOccurrences(of: "\(packagePrefix)::", with: ""))
}

private func fetchPackageVersions(client: GraphQlClient, packageAddress: Address) async throws
  -> [MovePackage]
{
  var versions: [MovePackage] = []
  var cursor: String?

  while true {
    let page = try await client.packageVersions(
      address: packageAddress,
      paginationFilter: forwardPage(cursor: cursor)
    )
    versions.append(contentsOf: page.data)
    if page.pageInfo.hasNextPage {
      cursor = page.pageInfo.endCursor
    } else {
      break
    }
  }

  return versions.sorted { $0.version().asU64() < $1.version().asU64() }
}

private func printObjectSamples(
  client: GraphQlClient,
  typeTag: String,
  hasKeyAbility: Bool,
  isGeneric: Bool
) async throws {
  if !hasKeyAbility {
    return
  }

  if isGeneric {
    print("    sample objects: skipped for generic type")
    return
  }

  let objects = try await client.objects(
    filter: ObjectFilter(typeTag: typeTag),
    paginationFilter: PaginationFilter(direction: .forward, limit: 3)
  )

  if objects.data.isEmpty {
    print("    sample objects: none found")
    return
  }

  print("    sample objects:")
  for object in objects.data {
    print("      - \(object.id().toHex()) (version \(object.version().asU64()))")
  }
  if objects.pageInfo.hasNextPage {
    print("      - ...")
  }
}

private func formatPolicyName(_ policy: UInt8) -> String {
  switch policy {
  case 0:
    return "Compatible"
  case 128:
    return "Additive"
  case 192:
    return "Dependency-only"
  default:
    return "Unknown (\(policy))"
  }
}

private func extractPolicy(contents: Value) -> UInt8? {
  guard
    let data = contents.data(using: .utf8),
    let rawJson = try? JSONSerialization.jsonObject(with: data),
    let json = rawJson as? [String: Any],
    let rawPolicy = json["policy"]
  else {
    return nil
  }

  if let number = rawPolicy as? NSNumber {
    return number.uint8Value
  }
  if let text = rawPolicy as? String {
    return UInt8(text)
  }

  return nil
}

private func resolveUpgradeCapId(
  client: GraphQlClient,
  packageId: ObjectId
) async throws -> ObjectId? {
  let page = try await client.transactionsEffects(
    filter: TransactionsFilter(changedObject: packageId),
    paginationFilter: PaginationFilter(direction: .forward, limit: 1)
  )

  for effects in page.data {
    let effectsV1 = effects.asV1()
    for changedObj in effectsV1.changedObjects() {
      guard case .objectWrite = changedObj.outputState else {
        continue
      }

      if let object = try await client.object(
        objectId: changedObj.objectId,
        version: effectsV1.lamportVersion()
      ),
        object.asOptStruct()?.structType == StructTag.newUpgradeCap()
      {
        return changedObj.objectId
      }
    }
  }

  return nil
}

private func sameObjectId(_ left: String?, _ right: String?) -> Bool {
  guard let left, let right else {
    return false
  }

  return left.caseInsensitiveCompare(right) == .orderedSame
}

private func programmableTransactionJson(_ tx: Transaction) throws -> [String: Any]? {
  guard
    let data = try tx.toJson().data(using: .utf8),
    let rawJson = try JSONSerialization.jsonObject(with: data) as? [String: Any],
    let txV1 = rawJson["1"] as? [String: Any],
    let kind = txV1["kind"] as? [String: Any],
    let kindName = kind["kind"] as? String,
    kindName == "programmable_transaction"
  else {
    return nil
  }

  return kind
}

private func isPackageMakeImmutableCall(_ command: [String: Any]) -> Bool {
  sameObjectId(command["package"] as? String, frameworkPackageId)
    && command["command"] as? String == "move_call"
    && command["module"] as? String == "package"
    && command["function"] as? String == "make_immutable"
}

private func inputMatchesObjectId(_ input: [String: Any], objectId: String) -> Bool {
  guard
    let inputType = input["type"] as? String,
    ["immutable_or_owned", "receiving", "shared"].contains(inputType)
  else {
    return false
  }

  return sameObjectId(input["object_id"] as? String, objectId)
}

private func publishesPackageAsImmutable(_ tx: Transaction) throws -> Bool {
  guard
    let programmableTx = try programmableTransactionJson(tx),
    let commands = programmableTx["commands"] as? [[String: Any]]
  else {
    return false
  }

  let publishIndexes = commands.enumerated().compactMap { index, command in
    command["command"] as? String == "publish" ? index : nil
  }
  guard publishIndexes.count == 1, let publishIndex = publishIndexes.first else {
    return false
  }

  for command in commands.dropFirst(publishIndex + 1) {
    guard
      isPackageMakeImmutableCall(command),
      let arguments = command["arguments"] as? [Any],
      arguments.count == 1,
      let argument = arguments[0] as? [String: Any],
      let result = argument["result"] as? NSNumber,
      result.intValue == publishIndex
    else {
      continue
    }

    return true
  }

  return false
}

private func usesUpgradeCapForMakeImmutable(
  _ tx: Transaction,
  upgradeCapId: ObjectId
) throws -> Bool {
  guard
    let programmableTx = try programmableTransactionJson(tx),
    let inputs = programmableTx["inputs"] as? [[String: Any]],
    let commands = programmableTx["commands"] as? [[String: Any]]
  else {
    return false
  }

  let upgradeCapInputs = inputs.enumerated().compactMap { index, input in
    inputMatchesObjectId(input, objectId: upgradeCapId.toHex()) ? index : nil
  }
  guard !upgradeCapInputs.isEmpty else {
    return false
  }

  for command in commands {
    guard
      isPackageMakeImmutableCall(command),
      let arguments = command["arguments"] as? [Any],
      arguments.count == 1,
      let argument = arguments[0] as? [String: Any],
      let input = argument["input"] as? NSNumber,
      upgradeCapInputs.contains(input.intValue)
    else {
      continue
    }

    return true
  }

  return false
}

private func wasPackagePublishedAsImmutable(
  client: GraphQlClient,
  packageId: ObjectId
) async throws -> Bool {
  var cursor: String?

  while true {
    let page = try await client.transactionsDataEffects(
      filter: TransactionsFilter(changedObject: packageId),
      paginationFilter: forwardPage(cursor: cursor)
    )

    for txData in page.data {
      if try publishesPackageAsImmutable(txData.tx.transaction) {
        return true
      }
    }

    if !page.pageInfo.hasNextPage {
      return false
    }

    cursor = page.pageInfo.endCursor
  }
}

private func wasUpgradeCapUsedForMakeImmutable(
  client: GraphQlClient,
  upgradeCapId: ObjectId
) async throws -> Bool {
  var cursor: String?

  while true {
    let page = try await client.transactionsDataEffects(
      filter: TransactionsFilter(inputObject: upgradeCapId),
      paginationFilter: forwardPage(cursor: cursor)
    )

    for txData in page.data {
      if try usesUpgradeCapForMakeImmutable(
        txData.tx.transaction,
        upgradeCapId: upgradeCapId
      ) {
        return true
      }
    }

    if !page.pageInfo.hasNextPage {
      return false
    }

    cursor = page.pageInfo.endCursor
  }
}

private func currentPackagePolicy(
  client: GraphQlClient,
  packageId: ObjectId
) async throws -> String {
  guard let upgradeCapId = try await resolveUpgradeCapId(client: client, packageId: packageId)
  else {
    if try await wasPackagePublishedAsImmutable(client: client, packageId: packageId) {
      return "Immutable"
    }
    return "Unavailable"
  }

  guard let contents = try await client.moveObjectContents(objectId: upgradeCapId) else {
    if try await wasUpgradeCapUsedForMakeImmutable(client: client, upgradeCapId: upgradeCapId) {
      return "Immutable"
    }
    return "Unavailable"
  }

  return extractPolicy(contents: contents).map(formatPolicyName) ?? "Unavailable"
}
