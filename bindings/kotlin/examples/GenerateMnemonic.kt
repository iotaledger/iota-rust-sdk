// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.MnemonicLength
import iota_sdk.generateMnemonic
import kotlin.io.println

fun main() {
    val mnemonic = generateMnemonic(null)
    println("24 word mnemonic: $mnemonic")
    val mnemonic12 = generateMnemonic(MnemonicLength.WORDS12)
    println("12 word mnemonic: $mnemonic12")
}
