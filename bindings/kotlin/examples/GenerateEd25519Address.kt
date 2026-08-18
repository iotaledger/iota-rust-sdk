// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Ed25519PrivateKey
import iota_sdk.base64Encode
import kotlin.io.println

fun main() {
    val privateKey = Ed25519PrivateKey.random()
    val privateKeyBech32 = privateKey.toBech32()
    val publicKey = privateKey.publicKey()
    val flaggedPublicKey = publicKey.toFlaggedBytes()
    val address = publicKey.deriveAddress()

    println("Private Key: ${privateKeyBech32}")
    println("Public Key: ${base64Encode(publicKey.toBytes())}")
    println("Public Key With Flag: ${base64Encode(flaggedPublicKey)}")
    println("Address: ${address.toHex()}")
}
