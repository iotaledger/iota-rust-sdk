// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct MoveViewCallExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    // ===========================================================================
    // Example 1: Using moveViewCall() with typed arguments (blake2b256)
    // ===========================================================================
    print("=== Example 1: moveViewCall() with typed arguments (blake2b256) ===")
    print()

    // Using typed arguments: an array of u8 values using the u8Vec constructor
    let hashArgs = [MoveViewArg.u8Vec(values: Data([0, 1, 2]))]

    let result = try await client.moveViewCall(
      functionName: "0x2::hash::blake2b256", typeArguments: nil, arguments: hashArgs)

    if result.error != nil {
      print("Error:", result.error!)
    } else if result.results != nil {
      print("Results:", result.results!)
    } else {
      print("No results")
    }

    // ===========================================================================
    // Example 2: Using moveViewCallJson() with JSON values (blake2b256)
    // ===========================================================================
    print()
    print("=== Example 2: moveViewCallJson() with JSON values (blake2b256) ===")
    print()

    let jsonResult = try await client.moveViewCallJson(
      functionName: "0x2::hash::blake2b256", typeArguments: nil, arguments: ["[0, 1, 2]"])

    if jsonResult.error != nil {
      print("JSON Error:", jsonResult.error!)
    } else if jsonResult.results != nil {
      print("JSON Results:", jsonResult.results!)
    } else {
      print("No JSON results")
    }

    // ===========================================================================
    // Example 3: Using moveViewCall() with typed arguments (auction)
    // ===========================================================================
    print()
    print("=== Example 3: moveViewCall() with typed arguments (auction) ===")
    print()

    let objectId = try ObjectId.fromHex(
      hex: "0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b")

    let auctionArgs = [
      MoveViewArg.objectId(value: objectId),
      MoveViewArg.string(value: "auc.iota"),
    ]

    let auctionResult = try await client.moveViewCall(
      functionName:
        "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
      typeArguments: nil, arguments: auctionArgs)

    if auctionResult.error != nil {
      print("Auction Error:", auctionResult.error!)
    } else if auctionResult.results != nil {
      print("Auction Results:", auctionResult.results!)
    } else {
      print("No auction results")
    }

    // ===========================================================================
    // Example 4: Using moveViewCallJson() with JSON values (auction)
    // ===========================================================================
    print()
    print("=== Example 4: moveViewCallJson() with JSON values (auction) ===")
    print()

    let auctionJsonResult = try await client.moveViewCallJson(
      functionName:
        "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
      typeArguments: nil,
      arguments: [
        "\"0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b\"",
        "\"auc.iota\"",
      ])

    if auctionJsonResult.error != nil {
      print("Auction JSON Error:", auctionJsonResult.error!)
    } else if auctionJsonResult.results != nil {
      print("Auction JSON Results:", auctionJsonResult.results!)
    } else {
      print("No auction JSON results")
    }
  }
}
