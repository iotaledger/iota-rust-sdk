// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GenerateEd25519AddressExample {
  static func main() throws {
    let privateKey = Ed25519PrivateKey.random()
    let privateKeyBech32 = try privateKey.toBech32()
    let publicKey = privateKey.publicKey()
    let flaggedPublicKey = publicKey.toFlaggedBytes()
    let address = publicKey.deriveAddress()

    print("Private Key: \(privateKeyBech32)")
    print("Public Key: \(base64Encode(input: publicKey.toBytes()))")
    print("Public Key With Flag: \(base64Encode(input: flaggedPublicKey))")
    print("Address: \(address.toHex())")
  }
}
