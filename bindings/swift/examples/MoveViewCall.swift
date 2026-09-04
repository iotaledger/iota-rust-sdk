// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

/// The `view_demo` package published on testnet.
let package = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4"
/// A shared `view_demo::shop::Shop` created when the package was published.
let shop = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20"

@main
struct MoveViewCallExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    // ===========================================================================
    // Example 1: Using moveViewCall() with typed arguments (primitives)
    // ===========================================================================
    print("=== Example 1: moveViewCall() with typed arguments (primitives) ===")
    print()

    let priceArgs = [MoveViewArg.u64(value: 100), MoveViewArg.u64(value: 25)]

    let result = try await client.moveViewCall(
      functionName: "\(package)::shop::discounted_price", typeArguments: nil, arguments: priceArgs)

    if result.error != nil {
      print("Error:", result.error!)
    } else if result.results != nil {
      print("Results:", result.results!)
    } else {
      print("No results")
    }

    // ===========================================================================
    // Example 2: Using moveViewCallJson() with JSON values (primitives)
    // ===========================================================================
    print()
    print("=== Example 2: moveViewCallJson() with JSON values (primitives) ===")
    print()

    // `u64` is passed as a string so large values survive JSON.
    let jsonResult = try await client.moveViewCallJson(
      functionName: "\(package)::shop::discounted_price", typeArguments: nil,
      arguments: ["\"100\"", "\"25\""])

    if jsonResult.error != nil {
      print("JSON Error:", jsonResult.error!)
    } else if jsonResult.results != nil {
      print("JSON Results:", jsonResult.results!)
    } else {
      print("No JSON results")
    }

    // ===========================================================================
    // Example 3: Using moveViewCall() with typed arguments (shared object)
    // ===========================================================================
    print()
    print("=== Example 3: moveViewCall() with typed arguments (shared object) ===")
    print()

    let objectId = try ObjectId.fromHex(hex: shop)

    let shopArgs = [
      MoveViewArg.objectId(value: objectId),
      MoveViewArg.u64(value: 1),
    ]

    let shopResult = try await client.moveViewCall(
      functionName: "\(package)::shop::sale_at", typeArguments: nil, arguments: shopArgs)

    if shopResult.error != nil {
      print("Shop Error:", shopResult.error!)
    } else if shopResult.results != nil {
      print("Shop Results:", shopResult.results!)
    } else {
      print("No shop results")
    }

    // ===========================================================================
    // Example 4: Using moveViewCallJson() with JSON values (shared object)
    // ===========================================================================
    print()
    print("=== Example 4: moveViewCallJson() with JSON values (shared object) ===")
    print()

    let shopJsonResult = try await client.moveViewCallJson(
      functionName: "\(package)::shop::sale_at", typeArguments: nil,
      arguments: ["\"\(shop)\"", "\"1\""])

    if shopJsonResult.error != nil {
      print("Shop JSON Error:", shopJsonResult.error!)
    } else if shopJsonResult.results != nil {
      print("Shop JSON Results:", shopJsonResult.results!)
    } else {
      print("No shop JSON results")
    }

    // ===========================================================================
    // Example 5: Using moveViewCallBuilder() to assemble the call
    // ===========================================================================
    print()
    print("=== Example 5: moveViewCallBuilder() ===")
    print()

    let packageId = try ObjectId.fromHex(hex: package)

    let builder = client.moveViewCallBuilder(
      package: packageId, module: "shop", function: "sale_at"
    ).arguments(arguments: [
      MoveViewArg.objectId(value: objectId),
      MoveViewArg.u64(value: 1),
    ])

    print("Builder Results:", try await builder.execute())
  }
}
