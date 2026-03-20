// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct FaucetExample {
  static func main() async {
    do {
      let address = try Address.fromHex(
        hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
      let faucetClient = FaucetClient.newLocalnet()
      let faucetReceipt = try await faucetClient.requestAndWait(address: address)
      if let receipt = faucetReceipt {
        print("Faucet receipt:")
        for coin in receipt.sent {
          print(
            "  Coin ID: \(coin.id.toHex()), Amount: \(coin.amount), Digest: \(coin.transferTxDigest.toBase58())"
          )
        }
      } else {
        print("Faucet receipt: None")
      }
    } catch {
      print("Error: \(error)")
      exit(1)
    }
  }
}
