// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.generateMnemonic
import kotlin.io.println

fun main() {
    val mnemonic = generateMnemonic(null)
    println("Mnemonic: $mnemonic")
}
