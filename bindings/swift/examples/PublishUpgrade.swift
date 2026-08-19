// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example allows you to publish any Move package by compiling it
// first using the `iota` binary. For demonstration purposes this example
// immediately upgrades the package after publishing it.
//
// ```bash
// cd /path/to/your/move/package
// export COMPILED_PACKAGE=$(iota move build --dump-bytecode-as-base64)
// ```
//
// With this example it is necessary to run a localnet:
//
// ```sh
// iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis
// ```

import Foundation
import IotaSDK

let precompiledPackage =
  #"{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}"#

@main
struct PublishUpgradeExample {
  static func main() async throws {
    // Read and parse the compiled package, or use the default package
    let packageDataJson: String
    if let envPackage = ProcessInfo.processInfo.environment["COMPILED_PACKAGE"] {
      print("Using custom Move package found in env var.")
      packageDataJson = envPackage
    } else {
      print("No compiled package found in env var. Using default.")
      packageDataJson = precompiledPackage
    }

    let packageData = try MovePackageData.fromJson(json: packageDataJson)
    let modules = packageData.modules()
    print("Modules: \(modules.count)")
    let dependencies = packageData.dependencies()
    print("Dependencies: \(dependencies.count)")
    let digest = packageData.digest()
    print("Digest: \(digest.toBase58())")

    // Create a random private key to derive a sender address and for signing
    let privateKey = Ed25519PrivateKey.random()
    let sender = privateKey.publicKey().deriveAddress()
    print("Sender: \(sender.toHex())")

    let client = GraphQlClient.newLocalnet()

    // Fund the sender address for gas payment
    let faucet = FaucetClient.newLocalnet()
    let faucetReceipt = try await faucet.requestAndWaitForFinalized(
      address: sender, client: client)
    if faucetReceipt == nil {
      throw NSError(
        domain: "PublishUpgrade", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to request coins from faucet"])
    }

    // Build the `publish` PTB
    let builder = TransactionBuilder(sender: sender).withClient(client: client)
    // Publish the package and receive the upgrade cap in return
    _ = builder.publishPackage(packageData: packageData, upgradeCapName: "upgrade_cap")
    // Transfer the upgrade cap to the sender address
    _ = builder.transferObjects(
      recipient: sender, objects: [PtbArgument.assigned(name: "upgrade_cap")])
    let tx = try await builder.finish()

    // Perform a dry-run first to check if everything is correct
    print("> Publishing package (dry run):")
    let dryResult = try await client.dryRunTx(tx: tx, skipChecks: false)
    if dryResult.error != nil {
      throw NSError(
        domain: "PublishUpgrade", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: \(dryResult.error!)"])
    }
    if dryResult.effects == nil {
      throw NSError(
        domain: "PublishUpgrade", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: no effects"])
    }
    print("Success")

    // Sign and execute the transaction (publish the package)
    print("> Publishing package:")
    let sig = try privateKey.signTransaction(transaction: tx)
    let effects = try await client.executeTx(
      signatures: [sig], tx: tx, waitFor: WaitForTx.finalized)
    print("Success")

    // Resolve UpgradeCap and PackageId via the client
    var upgradeCap: ObjectId?
    var packageId: ObjectId?
    for changedObj in effects.asV1().changedObjects {
      switch changedObj.outputState {
      case .objectWrite(_, let owner):
        let objectId = changedObj.objectId
        let obj = try await client.object(objectId: objectId, version: nil)
        guard let obj = obj else {
          throw NSError(
            domain: "PublishUpgrade", code: 1,
            userInfo: [
              NSLocalizedDescriptionKey: "Missing object \(objectId.toHex())"
            ])
        }
        if obj.asStruct().structType == StructTag.newUpgradeCap() {
          print("UpgradeCap: \(objectId.toHex())")
          print(
            "UpgradeCapOwner: \(owner.asAddress().toHex())")
          upgradeCap = objectId
        }
      case .packageWrite(let version, _):
        packageId = changedObj.objectId
        print("Package ID: \(packageId!.toHex())")
        print("Package version: \(version)")
      case .missing:
        break
      }
    }

    guard let upgradeCap = upgradeCap else {
      throw NSError(
        domain: "PublishUpgrade", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Missing upgrade cap"])
    }
    guard let packageId = packageId else {
      throw NSError(
        domain: "PublishUpgrade", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Missing package id"])
    }

    // Build the `upgrade` PTB
    let upgradeBuilder = TransactionBuilder(sender: sender).withClient(client: client)

    // Authorize the upgrade
    _ = try upgradeBuilder.moveCall(
      package: Address.framework(),
      module: Identifier(identifier: "package"),
      function: Identifier(identifier: "authorize_upgrade"),
      arguments: [
        PtbArgument.objectId(id: upgradeCap),
        PtbArgument.u8(value: UpgradePolicy.compatible().asU8()),
        PtbArgument.u8Vec(values: Data(digest.toBytes())),
      ],
      names: ["upgrade_ticket"]
    )

    // Upgrade the package to receive an upgrade receipt
    _ = upgradeBuilder.upgrade(
      packageId: packageId,
      packageData: packageData,
      upgradeTicket: PtbArgument.assigned(name: "upgrade_ticket"),
      name: "upgrade_receipt"
    )

    // Commit the upgrade using the receipt
    _ = try upgradeBuilder.moveCall(
      package: Address.framework(),
      module: Identifier(identifier: "package"),
      function: Identifier(identifier: "commit_upgrade"),
      arguments: [
        PtbArgument.objectId(id: upgradeCap),
        PtbArgument.assigned(name: "upgrade_receipt"),
      ]
    )

    let upgradeTx = try await upgradeBuilder.finish()

    // Perform a dry-run first to check if everything is correct
    print("> Upgrading package (dry run):")
    let upgradeDryResult = try await client.dryRunTx(tx: upgradeTx, skipChecks: false)
    if upgradeDryResult.error != nil {
      throw NSError(
        domain: "PublishUpgrade", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: \(upgradeDryResult.error!)"])
    }
    if upgradeDryResult.effects == nil {
      throw NSError(
        domain: "PublishUpgrade", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: no effects"])
    }
    print("Success")

    // Sign and execute the transaction (upgrade the package)
    print("> Upgrading package:")
    let upgradeSig = try privateKey.signTransaction(transaction: upgradeTx)
    let upgradeEffects = try await client.executeTx(signatures: [upgradeSig], tx: upgradeTx)
    print("Success")

    // Print the new package version (should now be 2)
    for changedObj in upgradeEffects.asV1().changedObjects {
      if case .packageWrite(let version, _) = changedObj.outputState {
        print("New Package ID: \(changedObj.objectId.toHex())")
        print("New Package version: \(version)")
      }
    }
  }
}
