// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

private func forwardPage(cursor: String? = nil) -> PaginationFilter {
  PaginationFilter(direction: .forward, cursor: cursor)
}

private func formatFunctionSignature(_ signature: String, packagePrefix: String) -> String {
  signature.replacingOccurrences(of: "\(packagePrefix)::", with: "")
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

  return versions.sorted { $0.version() < $1.version() }
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
    print("      - \(object.objectId().toHex()) (version \(object.version()))")
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
    for changedObj in effectsV1.changedObjects {
      guard case .objectWrite = changedObj.outputState else {
        continue
      }

      if let object = try await client.object(
        objectId: changedObj.objectId,
        version: effectsV1.lamportVersion
      ),
        object.asStructOpt()?.structType == StructTag.newUpgradeCap()
      {
        return changedObj.objectId
      }
    }
  }

  return nil
}

private func currentPackagePolicy(
  client: GraphQlClient,
  packageId: ObjectId
) async throws -> String {
  guard let upgradeCapId = try await resolveUpgradeCapId(client: client, packageId: packageId)
  else {
    return "Unavailable"
  }

  guard let contents = try await client.moveObjectContents(objectId: upgradeCapId) else {
    return "Unavailable"
  }

  return extractPolicy(contents: contents).map(formatPolicyName) ?? "Unavailable"
}

@main
struct PackageInspectExample {
  static func main() async throws {
    guard CommandLine.arguments.count > 1 else {
      throw NSError(
        domain: "PackageInspect", code: 1,
        userInfo: [
          NSLocalizedDescriptionKey:
            "Usage: swift run PackageInspect <PACKAGE_ID>"
        ])
    }
    let packageId = CommandLine.arguments[1]

    let packageAddress = try Address.fromHex(hex: packageId)
    let client = GraphQlClient.newTestnet()

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

    print("Requested package id: \(packageId)")
    print("Resolved package id: \(packagePrefix)")
    print("Resolved version: \(package.version())")
    print("Latest version: \(latestPackage.version()) (\(latestPackage.id().toHex()))")
    print("Current package policy: \(try await currentPackagePolicy(client: client, packageId: package.id()))")
    print()

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
      print("- v\(version.version()) -> \(version.id().toHex())\(suffix)")
    }
    print()

    print("Dependencies:")
    let dependencies = package.linkageTable().sorted { $0.key.toHex() < $1.key.toHex() }
    if dependencies.isEmpty {
      print("- none")
    } else {
      for (originalId, upgrade) in dependencies {
        print(
          "- \(originalId.toHex()) -> \(upgrade.upgradedId.toHex()) @ v\(upgrade.upgradedVersion)"
        )
      }
    }
    print()

    print("Modules, functions, and types:")
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
          print("    - \(formatFunctionSignature(String(describing: function), packagePrefix: packagePrefix))")
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
