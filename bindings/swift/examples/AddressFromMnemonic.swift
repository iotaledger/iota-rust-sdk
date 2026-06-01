// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct AddressFromMnemonicExample {
  static func main() throws {
    let mnemonic = "round attack kitchen wink winter music trip tiny nephew hire orange what"

    let ed25519Key = try Ed25519PrivateKey.fromMnemonic(phrase: mnemonic)
    let ed25519Bech32 = try ed25519Key.toBech32()
    let ed25519PubKey = ed25519Key.publicKey()
    let ed25519Flagged = ed25519PubKey.toFlaggedBytes()
    let ed25519Address = ed25519PubKey.deriveAddress()

    print("Ed25519\n---")
    print("Private Key: \(ed25519Bech32)")
    print("Public Key: \(base64Encode(input: ed25519PubKey.toBytes()))")
    print("Public Key With Flag: \(base64Encode(input: ed25519Flagged))")
    print("Address: \(ed25519Address.toHex())")

    let secp256k1Key = try Secp256k1PrivateKey.fromMnemonic(phrase: mnemonic, accountIndex: 1)
    let secp256k1Bech32 = try secp256k1Key.toBech32()
    let secp256k1PubKey = secp256k1Key.publicKey()
    let secp256k1Flagged = secp256k1PubKey.toFlaggedBytes()
    let secp256k1Address = secp256k1PubKey.deriveAddress()

    print("\nSecp256k1\n---")
    print("Private Key: \(secp256k1Bech32)")
    print("Public Key: \(base64Encode(input: secp256k1PubKey.toBytes()))")
    print("Public Key With Flag: \(base64Encode(input: secp256k1Flagged))")
    print("Address: \(secp256k1Address.toHex())")

    let secp256r1Key = try Secp256r1PrivateKey.fromMnemonicWithPath(
      phrase: mnemonic, path: "m/74'/4218'/0'/0/2")
    let secp256r1Bech32 = try secp256r1Key.toBech32()
    let secp256r1PubKey = secp256r1Key.publicKey()
    let secp256r1Flagged = secp256r1PubKey.toFlaggedBytes()
    let secp256r1Address = secp256r1PubKey.deriveAddress()

    print("\nSecp256r1\n---")
    print("Private Key: \(secp256r1Bech32)")
    print("Public Key: \(base64Encode(input: secp256r1PubKey.toBytes()))")
    print("Public Key With Flag: \(base64Encode(input: secp256r1Flagged))")
    print("Address: \(secp256r1Address.toHex())")
  }
}
