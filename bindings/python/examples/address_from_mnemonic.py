# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

MNEMONIC = "round attack kitchen wink winter music trip tiny nephew hire orange what"


def main():
    private_key = Ed25519PrivateKey.from_mnemonic(MNEMONIC)
    private_key_bech32 = private_key.to_bech32()
    public_key = private_key.public_key()
    flagged_public_key = public_key.to_flagged_bytes()
    address = public_key.derive_address()

    print(f"Ed25519\n---")
    print(f"Private Key: {private_key_bech32}")
    print(f"Public Key: {base64_encode(public_key.to_bytes())}")
    print(f"Public Key With Flag: {base64_encode(flagged_public_key)}")
    print(f"Address: {address.to_hex()}")

    private_key = Secp256k1PrivateKey.from_mnemonic(MNEMONIC)
    private_key_bech32 = private_key.to_bech32()
    public_key = private_key.public_key()
    flagged_public_key = public_key.to_flagged_bytes()
    address = public_key.derive_address()

    print(f"\nSecp256k1\n---")
    print(f"Private Key: {private_key_bech32}")
    print(f"Public Key: {base64_encode(public_key.to_bytes())}")
    print(f"Public Key With Flag: {base64_encode(flagged_public_key)}")
    print(f"Address: {address.to_hex()}")

    private_key = Secp256r1PrivateKey.from_mnemonic(MNEMONIC)
    private_key_bech32 = private_key.to_bech32()
    public_key = private_key.public_key()
    flagged_public_key = public_key.to_flagged_bytes()
    address = public_key.derive_address()

    print(f"\nSecp256r1\n---")
    print(f"Private Key: {private_key_bech32}")
    print(f"Public Key: {base64_encode(public_key.to_bytes())}")
    print(f"Public Key With Flag: {base64_encode(flagged_public_key)}")
    print(f"Address: {address.to_hex()}")


if __name__ == "__main__":
    main()
