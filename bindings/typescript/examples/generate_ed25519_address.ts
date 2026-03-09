// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { Ed25519PrivateKey, base64Encode } from "../lib";

function main() {
  const privateKey = Ed25519PrivateKey.generate();
  const privateKeyBech32 = privateKey.toBech32();
  const publicKey = privateKey.publicKey();
  const flaggedPublicKey = publicKey.toFlaggedBytes();
  const address = publicKey.deriveAddress();

  console.log(`Private Key: ${privateKeyBech32}`);
  console.log(`Public Key: ${base64Encode(publicKey.toBytes())}`);
  console.log(`Public Key With Flag: ${base64Encode(flaggedPublicKey)}`);
  console.log(`Address: ${address.toHex()}`);
}

main();
