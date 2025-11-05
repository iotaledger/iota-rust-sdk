// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Ed25519PrivateKey
import iota_sdk.Secp256k1PrivateKey
import iota_sdk.Secp256r1PrivateKey
import iota_sdk.base64Encode
import kotlin.io.println

const val MNEMONIC = "round attack kitchen wink winter music trip tiny nephew hire orange what"

fun main() {
  val privateKeyEd25519 = Ed25519PrivateKey.fromMnemonic(MNEMONIC)
  val privateKeyEd25519Bech32 = privateKeyEd25519.toBech32()
  val publicKeyEd25519 = privateKeyEd25519.publicKey()
  val flaggedPublicKeyEd25519 = publicKeyEd25519.toFlaggedBytes()
  val addressEd25519 = publicKeyEd25519.deriveAddress()

  println("Ed25519\n---")
  println("Private Key: ${privateKeyEd25519Bech32}")
  println("Public Key: ${base64Encode(publicKeyEd25519.toBytes())}")
  println("Public Key With Flag: ${base64Encode(flaggedPublicKeyEd25519)}")
  println("Address: ${addressEd25519.toHex()}")

  val privateKeySecp256k1 = Secp256k1PrivateKey.fromMnemonic(MNEMONIC, 1uL)
  val privateKeySecp256k1Bech32 = privateKeySecp256k1.toBech32()
  val publicKeySecp256k1 = privateKeySecp256k1.publicKey()
  val flaggedPublicKeySecp256k1 = publicKeySecp256k1.toFlaggedBytes()
  val addressSecp256k1 = publicKeySecp256k1.deriveAddress()

  println("\nSecp256k1\n---")
  println("Private Key: ${privateKeySecp256k1Bech32}")
  println("Public Key: ${base64Encode(publicKeySecp256k1.toBytes())}")
  println("Public Key With Flag: ${base64Encode(flaggedPublicKeySecp256k1)}")
  println("Address: ${addressSecp256k1.toHex()}")

  val privateKeySecp256r1 = Secp256r1PrivateKey.fromMnemonicWithPath(MNEMONIC, "m/74'/4218'/0'/0/2")
  val privateKeySecp256r1Bech32 = privateKeySecp256r1.toBech32()
  val publicKeySecp256r1 = privateKeySecp256r1.publicKey()
  val flaggedPublicKeySecp256r1 = publicKeySecp256r1.toFlaggedBytes()
  val addressSecp256r1 = publicKeySecp256r1.deriveAddress()

  println("\nSecp256r1\n---")
  println("Private Key: ${privateKeySecp256r1Bech32}")
  println("Public Key: ${base64Encode(publicKeySecp256r1.toBytes())}")
  println("Public Key With Flag: ${base64Encode(flaggedPublicKeySecp256r1)}")
  println("Address: ${addressSecp256r1.toHex()}")
}
