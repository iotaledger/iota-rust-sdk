# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import Ed25519PrivateKey, base64_encode


def main():
    private_key = Ed25519PrivateKey.random()
    private_key_bech32 = private_key.to_bech32()
    public_key = private_key.public_key()
    flagged_public_key = public_key.to_flagged_bytes()
    address = public_key.derive_address()

    print(f"Private Key: {private_key_bech32}")
    print(f"Public Key: {base64_encode(public_key.to_bytes())}")
    print(f"Public Key With Flag: {base64_encode(flagged_public_key)}")
    print(f"Address: {address.to_hex()}")


if __name__ == "__main__":
    main()
