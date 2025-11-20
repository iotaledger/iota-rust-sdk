# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import generate_mnemonic


def main():
    mnemonic = generate_mnemonic(None)
    print("Mnemonic:", mnemonic)


if __name__ == "__main__":
    main()
