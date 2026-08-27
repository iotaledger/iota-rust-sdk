// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

let abstractAccountPrecompiledPackage =
  #"{"modules":["oRzrCwYAAAALAQAUAhQmAzorBGUGBWtPB7oBwAII+gNgBtoECRDjBCoKjQULDJgFQgAJAgkCCwINAg4CFgIXAhoCGwEKAAEMAAAAAgACAgIAAwMHAQgBBAQIAAUIBAAGBQgACAcCAAkGBwAAEwABAAAUAgEAAAwDAQABDwsBAQgDEAkKAQgFFQQFAAcYBwEBDAkZDA0ABgYEBgMGAggBBwgHAAQIAAYIBggICAgFBggACAgGCAQGCAIGCAcBBwgHAQgFAQgAAQkAAQsDAQgAAwYIBggICAgBCwMBCQACCQALAwEJAAEKAgEICAdBQ0NPVU5UB0FjY291bnQLQXV0aENvbnRleHQaQXV0aGVudGljYXRvckZ1bmN0aW9uUmVmVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlFmF1dGhlbnRpY2F0b3JfZnVuY3Rpb24FY2xvY2sRY3JlYXRlX2FjY291bnRfdjEbY3JlYXRlX2F1dGhfZnVuY3Rpb25fcmVmX3YxC2R1bW15X2ZpZWxkAmlkBGluaXQJbGlua19hdXRoA25ldwZvYmplY3QQcGFja2FnZV9tZXRhZGF0YRNwdWJsaWNfc2hhcmVfb2JqZWN0BnN0cmluZwh0cmFuc2Zlcgp0eF9jb250ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCgIGBWhlbGxvDmlvdGE6Om1ldGFkYXRhGgEAAAAAAAAAEQEMYXV0aGVudGljYXRlAQABAAIBEggFAQIBEQEAAAAAAQULAREFEgA4AAIBAQAACAkLAQsCCwM4AQwECwALBDgCAgIBAAABCQsBBwARByEEBgUIBgAAAAAAAAAAJwIA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[236,68,86,252,91,28,224,206,146,112,120,93,47,52,14,168,169,132,252,75,45,104,10,116,171,91,155,100,66,111,66,147]}"#

@main
struct AbstractAccountExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()
    let accountId = try await setupAccount(client: client)
    let fromAddress = accountId.toAddress()
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    // Fund the sender address for gas payment
    let faucet = FaucetClient.newLocalnet()
    let faucetReceipt = try await faucet.requestAndWaitForFinalized(
      address: fromAddress, client: client)
    if faucetReceipt == nil {
      throw NSError(
        domain: "AbstractAccount", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to request coins from faucet"])
    }

    let builder = client.transactionBuilder(sender: fromAddress)
    _ = builder.sendIota(
      recipient: toAddress, amount: PtbArgument.u64(value: 5_000_000_000))

    let moveAuthenticator = try await MoveAuthenticatorBuilder(
      accountId: accountId,
      callArgs: [
        PtbArgument.string(string: "hello"),
        PtbArgument.shared(id: ObjectId.clock()),
      ],
      typeArgs: []
    ).finish(client: client)

    let signer = TransactionSigner.fromMoveAuthenticator(
      auth: moveAuthenticator)
    let effects = try await builder.execute(
      signer: signer, waitFor: WaitForTx.finalized)

    print("Sending IOTA via abstract account: \(effects.asV1().status())")
  }

  static func setupAccount(client: GraphQlClient) async throws -> ObjectId {
    // Parse the precompiled move package
    let packageData = try MovePackageData.fromJson(json: abstractAccountPrecompiledPackage)

    // Create a random private key to derive a sender address
    let privateKey = Ed25519PrivateKey.random()
    let sender = privateKey.publicKey().deriveAddress()

    // Fund the sender address for gas payment
    let faucet = FaucetClient.newLocalnet()
    let faucetReceipt = try await faucet.requestAndWaitForFinalized(
      address: sender, client: client)
    if faucetReceipt == nil {
      throw NSError(
        domain: "AbstractAccount", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to request coins from faucet"])
    }

    // Build the `publish` PTB
    let builder = client.transactionBuilder(sender: sender)
    // Publish the package and receive the upgrade cap
    _ = builder.publishPackage(packageData: packageData, upgradeCapName: "upgrade_cap")
    // Transfer the upgrade cap to the sender address
    _ = builder.transferObjects(
      recipient: sender, objects: [PtbArgument.assigned(name: "upgrade_cap")])

    // Sign and execute the transaction (publish the package)
    let signer = TransactionSigner.fromEd25519(key: privateKey)
    let effects = try await builder.execute(
      signer: signer, waitFor: WaitForTx.finalized)

    print("Publishing package: \(effects.asV1().status())\n")

    // Get package, package metadata and account IDs from the effects
    var packageId: ObjectId?
    var packageMetadataId: ObjectId?
    var accountId: ObjectId?

    for changedObj in effects.asV1().changedObjects() {
      switch changedObj.outputState {
      case .packageWrite(_, _):
        packageId = changedObj.objectId
      case .objectWrite(_, _):
        let objectId = changedObj.objectId
        let obj = try await client.object(objectId: objectId, version: nil)

        if let obj = obj {
          let typeName = obj.asStruct().structType.name().asStr()
          if typeName == "PackageMetadataV1" {
            packageMetadataId = objectId
          }
          if typeName == "Account" {
            accountId = objectId
          }
        }
      case .missing:
        break
      }
    }

    guard let packageId = packageId else {
      throw NSError(
        domain: "AbstractAccount", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Missing package id"])
    }
    guard let packageMetadataId = packageMetadataId else {
      throw NSError(
        domain: "AbstractAccount", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Missing package metadata id"])
    }
    guard let accountId = accountId else {
      throw NSError(
        domain: "AbstractAccount", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Missing account id"])
    }

    print("Package ID: \(packageId.toHex())")
    print("PackageMetadataV1 ID: \(packageMetadataId.toHex())")
    print("Account ID: \(accountId.toHex())\n")

    // Build the `link_auth` PTB
    let linkBuilder = client.transactionBuilder(sender: sender)
    _ = try linkBuilder.moveCall(
      package: packageId.toAddress(),
      module: Identifier(identifier: "account"),
      function: Identifier(identifier: "link_auth"),
      arguments: [
        PtbArgument.sharedMut(id: accountId),
        PtbArgument.objectId(id: packageMetadataId),
        PtbArgument.string(string: "account"),
        PtbArgument.string(string: "authenticate"),
      ]
    )

    // Sign and execute the transaction (link the authenticator)
    let linkEffects = try await linkBuilder.execute(
      signer: signer, waitFor: WaitForTx.finalized)

    print("Linking account to authenticate method: \(linkEffects.asV1().status())\n")

    return accountId
  }
}
