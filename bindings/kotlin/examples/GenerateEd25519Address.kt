// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Ed25519PrivateKey
import iota_sdk.base64Encode
import kotlin.io.println

fun main() {
    val privateKey = Ed25519PrivateKey.generate()
    val publicKey = privateKey.publicKey()
    val publicKeyBytes = publicKey.toBytes()
    val flaggedPublicKey = byteArrayOf((publicKey.scheme().ordinal + 1).toByte()) + publicKeyBytes
    val address = publicKey.deriveAddress()

    println("Private Key: ${base64Encode(privateKey.toDer())}")
    println("Public Key: ${base64Encode(publicKeyBytes)}")
    println("Public Key With Flag: ${base64Encode(flaggedPublicKey)}")
    println("Address: ${address.toHex()}")
}
