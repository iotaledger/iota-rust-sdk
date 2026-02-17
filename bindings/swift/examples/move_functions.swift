// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct MoveFunctionsExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let packageAddress = try Address.fromHex(
      hex: "0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")

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
