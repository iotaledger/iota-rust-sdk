// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct GasStationExample {
  static func main() async {
    do {
      let client = GraphQlClient.newLocalnet()
      let gasStationUrl = "http://0.0.0.0:9527"
      let gasStationAuthToken = "test"
      let keypair = Ed25519PrivateKey.random()
      let sender = keypair.publicKey().deriveAddress()
      let signer = TransactionSigner.fromEd25519(key: keypair)

      let builder = client.transactionBuilder(sender: sender)

      _ = try builder.moveCall(
        package: Address.std(),
        module: Identifier(identifier: "u64"),
        function: Identifier(identifier: "sqrt"),
        arguments: [PtbArgument.u64(value: 64)]
      )

      _ = builder.gasStationSponsor(
        url: gasStationUrl,
        headers: ["Authorization": ["Bearer \(gasStationAuthToken)"]])

      let res = try await builder.execute(signer: signer)

      print(res)

      print("Sponsored transaction was successful!")
    } catch {
      print("Error: \(error)")
      exit(1)
    }
  }
}
