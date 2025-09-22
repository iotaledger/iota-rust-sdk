// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Ed25519PrivateKey
import java.util.Base64
import kotlin.io.println

fun main() {
    val privateKey = Ed25519PrivateKey.generate()
    val publicKey = privateKey.publicKey()
    val publicKeyBytes = publicKey.toBytes()
    val flaggedPublicKey = byteArrayOf((publicKey.scheme().ordinal + 1).toByte()) + publicKeyBytes
    val address = publicKey.deriveAddress()

    println("Private Key: ${Base64.getEncoder().encodeToString(privateKey.toDer())}")
    println("Public Key: ${Base64.getEncoder().encodeToString(publicKeyBytes)}")
    println("Public Key With Flag: ${Base64.getEncoder().encodeToString(flaggedPublicKey)}")
    println("Address: ${address.toHex()}")
}
