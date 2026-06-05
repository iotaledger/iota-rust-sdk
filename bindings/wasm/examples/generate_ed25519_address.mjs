// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  base64Encode,
  Ed25519PrivateKey,
  uniffiInitAsync,
} from "@iota/sdk-wasm";

await uniffiInitAsync();

const privateKey = Ed25519PrivateKey.generate();
const privateKeyBech32 = privateKey.toBech32();
const publicKey = privateKey.publicKey();
const flaggedPublicKey = publicKey.toFlaggedBytes();
const address = publicKey.deriveAddress();

console.log(`Private Key: ${privateKeyBech32}`);
console.log(`Public Key: ${base64Encode(publicKey.toBytes())}`);
console.log(`Public Key With Flag: ${base64Encode(flaggedPublicKey)}`);
console.log(`Address: ${address.toHex()}`);
