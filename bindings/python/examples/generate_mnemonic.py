# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import generate_mnemonic, MnemonicLength


def main():
    mnemonic = generate_mnemonic(None)
    print("24 word mnemonic:", mnemonic)
    mnemonic = generate_mnemonic(MnemonicLength.WORDS12)
    print("12 word mnemonic:", mnemonic)


if __name__ == "__main__":
    main()
