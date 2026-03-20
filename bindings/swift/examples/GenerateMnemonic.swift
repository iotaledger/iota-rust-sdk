// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GenerateMnemonicExample {
  static func main() throws {
    let mnemonic24 = generateMnemonic(wordCount: nil)
    print("24 word mnemonic:", mnemonic24)
    let mnemonic12 = generateMnemonic(wordCount: MnemonicLength.words12)
    print("12 word mnemonic:", mnemonic12)
  }
}
