// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct DevInspectExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let sender = Address.zero()

    let iotaNamesPackageAddress = try Address.fromHex(
      hex: "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea")
    let iotaNamesObjectId = try ObjectId.fromHex(
      hex: "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")
    let stdAddress = Address.std()

    let name = "name.iota"
    print("Looking up name: \(name)")

    let builder = client.transactionBuilder(sender: sender)

    // 1. Get the registry
    _ = try builder.moveCall(
      package: iotaNamesPackageAddress,
      module: Identifier(identifier: "iota_names"),
      function: Identifier(identifier: "registry"),
      arguments: [PtbArgument.sharedMut(id: iotaNamesObjectId)],
      typeArgs: [
        TypeTag.newStruct(
          structTag: StructTag(
            address: iotaNamesPackageAddress,
            module: Identifier(identifier: "registry"),
            name: Identifier(identifier: "Registry")
          ))
      ],
      names: ["iota_names"]
    )

    // 2. Create name from string
    _ = try builder.moveCall(
      package: iotaNamesPackageAddress,
      module: Identifier(identifier: "name"),
      function: Identifier(identifier: "new"),
      arguments: [PtbArgument.string(string: name)],
      names: ["name"]
    )

    // 3. Lookup name record
    _ = try builder.moveCall(
      package: iotaNamesPackageAddress,
      module: Identifier(identifier: "registry"),
      function: Identifier(identifier: "lookup"),
      arguments: [PtbArgument.assigned(name: "iota_names"), PtbArgument.assigned(name: "name")],
      names: ["name_record_opt"]
    )

    // 4. Borrow name record from option
    _ = try builder.moveCall(
      package: stdAddress,
      module: Identifier(identifier: "option"),
      function: Identifier(identifier: "borrow"),
      arguments: [PtbArgument.assigned(name: "name_record_opt")],
      typeArgs: [
        TypeTag.newStruct(
          structTag: StructTag(
            address: iotaNamesPackageAddress,
            module: Identifier(identifier: "name_record"),
            name: Identifier(identifier: "NameRecord")
          ))
      ],
      names: ["name_record"]
    )

    // 5. Get target address from name record
    _ = try builder.moveCall(
      package: iotaNamesPackageAddress,
      module: Identifier(identifier: "name_record"),
      function: Identifier(identifier: "target_address"),
      arguments: [PtbArgument.assigned(name: "name_record")],
      names: ["target_address_opt"]
    )

    // 6. Borrow address from option
    _ = try builder.moveCall(
      package: stdAddress,
      module: Identifier(identifier: "option"),
      function: Identifier(identifier: "borrow"),
      arguments: [PtbArgument.assigned(name: "target_address_opt")],
      typeArgs: [TypeTag.newAddress()],
      names: ["target_address"]
    )

    let res = try await builder.dryRun(skipChecks: true)

    if res.error != nil {
      throw NSError(
        domain: "DevInspect", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to lookup name: \(res.error!)"])
    }

    // Extract the resolved address from the last result
    if res.results.count > 0 {
      let lastEffect = res.results[res.results.count - 1]
      if lastEffect.returnValues.count > 0 {
        let returnValue = lastEffect.returnValues[0]
        if returnValue.typeTag.isAddress() && returnValue.bcs.count == 32 {
          let resolvedAddress = try Address.fromBytes(bytes: returnValue.bcs)
          print("Resolved address: \(resolvedAddress.toHex())")
        } else {
          print(
            "Last result is not an address type or has wrong length: \(returnValue.bcs.count)"
          )
        }
      } else {
        print("No return value in last effect")
      }
    } else {
      print("No results found")
    }
  }
}
