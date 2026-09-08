// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

/// The `view_demo` package published on testnet.
let package = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4"
/// A shared `view_demo::shop::Shop` created when the package was published.
let shop = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20"

func describe(_ outputs: ViewFunctionCallOutputs) -> String {
  if let returnValues = outputs.returnValues {
    return "returned \(returnValues.compactMap { $0.json })"
  }
  return "aborted (\(outputs.executionError?.source ?? ""))"
}

@main
struct GrpcViewFunctionCallExample {
  static func main() async throws {
    let client = try GrpcClient.newTestnet()

    // A single call. `discounted_price` is declared `#[view]` in the package.
    let outputs = try await client.viewFunctionCall(
      fqFunctionName: "\(package)::shop::discounted_price",
      typeArgs: nil,
      callArgs: [MoveViewArg.u64(value: 100), MoveViewArg.u64(value: 25)],
      readMask: nil)
    print("discounted_price:", describe(outputs))

    // Three calls in one request: the call from above, the same function with
    // a discount over 100% so that it aborts, and a function that is not
    // declared `#[view]`. Each call runs on its own, so the rejected one does
    // not affect the others.
    let shopId = try ObjectId.fromHex(hex: shop)
    let results = try await client.viewFunctionCalls(
      functionCalls: [
        ViewFunctionCallInput(
          fqFunctionName: "\(package)::shop::discounted_price",
          callArgs: [MoveViewArg.u64(value: 100), MoveViewArg.u64(value: 25)]),
        ViewFunctionCallInput(
          fqFunctionName: "\(package)::shop::discounted_price",
          callArgs: [MoveViewArg.u64(value: 100), MoveViewArg.u64(value: 200)]),
        ViewFunctionCallInput(
          fqFunctionName: "\(package)::shop::record_sale",
          callArgs: [MoveViewArg.objectId(value: shopId), MoveViewArg.u64(value: 5)]),
      ],
      readMask: nil)

    for (name, result) in zip(["priced", "over-discounted", "record_sale"], results) {
      if let callOutputs = result.outputs {
        print("\(name):", describe(callOutputs))
      } else {
        print("\(name): rejected by the node (\(result.error ?? ""))")
      }
    }
  }
}
