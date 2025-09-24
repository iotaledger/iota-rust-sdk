# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import Ed25519PrivateKey, base64_encode


def main():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.to_bytes()
    flagged_public_key = bytes([public_key.scheme().value]) + public_key_bytes
    address = public_key.derive_address()

    print(f"Private Key: {base64_encode(private_key.to_der())}")
    print(f"Public Key: {base64_encode(public_key_bytes)}")
    print(f"Public Key With Flag: {base64_encode(flagged_public_key)}")
    print(f"Address: {address.to_hex()}")


if __name__ == "__main__":
    main()
