# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import base64
from lib.iota_sdk_ffi import Ed25519PrivateKey


def main():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.to_bytes()
    flagged_public_key = bytes([public_key.scheme().value]) + public_key_bytes
    address = public_key.derive_address()

    print(f"Private Key: {base64.b64encode(private_key.to_der()).decode()}")
    print(f"Public Key: {base64.b64encode(public_key_bytes).decode()}")
    print(f"Public Key With Flag: {base64.b64encode(flagged_public_key).decode()}")
    print(f"Address: {address.to_hex()}")


if __name__ == "__main__":
    main()
