// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct MoveFunctionsExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    // Inspect the IOTA framework package (0x2). It is present on every network
    // including localnet.
    let packageAddress = Address.framework()

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
