// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

private func forwardPage(cursor: String? = nil) -> PaginationFilter {
  PaginationFilter(direction: .forward, cursor: cursor)
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
  isGeneric: Bool
) async throws {
  if isGeneric {
    print("    sample objects: skipped for generic type")
    return
  }

  let objects = try await client.objects(
    filter: ObjectFilter(typeTag: typeTag),
    paginationFilter: forwardPage()
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
          print("    - \(function)")
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
          let isGeneric = !(structType.typeParameters ?? []).isEmpty
          try await printObjectSamples(client: client, typeTag: typeTag, isGeneric: isGeneric)
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
