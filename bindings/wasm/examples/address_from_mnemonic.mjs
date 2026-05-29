// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  base64Encode,
  Ed25519PrivateKey,
  Secp256k1PrivateKey,
  Secp256r1PrivateKey,
  uniffiInitAsync,
} from "iota-sdk-wasm";

await uniffiInitAsync();

const MNEMONIC =
  "round attack kitchen wink winter music trip tiny nephew hire orange what";

function printKey(label, privateKey) {
  const publicKey = privateKey.publicKey();
  console.log(`${label}\n---`);
  console.log(`Private Key: ${privateKey.toBech32()}`);
  console.log(`Public Key: ${base64Encode(publicKey.toBytes())}`);
  console.log(
    `Public Key With Flag: ${base64Encode(publicKey.toFlaggedBytes())}`,
  );
  console.log(`Address: ${publicKey.deriveAddress().toHex()}`);
}

printKey("Ed25519", Ed25519PrivateKey.fromMnemonic(MNEMONIC));
console.log();
printKey("Secp256k1", Secp256k1PrivateKey.fromMnemonic(MNEMONIC, 1));
console.log();
printKey(
  "Secp256r1",
  Secp256r1PrivateKey.fromMnemonicWithPath(MNEMONIC, "m/74'/4218'/0'/0/2"),
);
