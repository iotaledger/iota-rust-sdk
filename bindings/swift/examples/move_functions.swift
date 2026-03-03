// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct MoveFunctionsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let packageAddress = try Address.fromHex(
      hex: "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d")

    guard let package = try await client.package(address: packageAddress) else {
      throw NSError(
        domain: "MoveFunctions", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "missing package"])
    }

    for (moduleId, _) in package.modules() {
      let module = try await client.normalizedMoveModule(
        package: packageAddress,
        module: moduleId.asStr()
      )
      guard let module = module else {
        print("module `\(moduleId.asStr())` not found")
        return
      }
      if let functions = module.functions {
        print("Module: \(moduleId.asStr())")
        for fun in functions.nodes {
          print("- \(fun)")
        }
        print()
      }
    }
  }
}
