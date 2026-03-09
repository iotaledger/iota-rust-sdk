// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Ed25519PrivateKey,
  Secp256k1PrivateKey,
  Secp256r1PrivateKey,
  base64Encode,
} from "../lib";

function main() {
  const mnemonic = "round attack kitchen wink winter music trip tiny nephew hire orange what";

  const ed25519Key = Ed25519PrivateKey.fromMnemonic(mnemonic, 0n, "");
  const ed25519Bech32 = ed25519Key.toBech32();
  const ed25519PubKey = ed25519Key.publicKey();
  const ed25519FlaggedPubKey = ed25519PubKey.toFlaggedBytes();
  const ed25519Address = ed25519PubKey.deriveAddress();

  console.log("Ed25519\n---");
  console.log(`Private Key: ${ed25519Bech32}`);
  console.log(`Public Key: ${base64Encode(ed25519PubKey.toBytes())}`);
  console.log(`Public Key With Flag: ${base64Encode(ed25519FlaggedPubKey)}`);
  console.log(`Address: ${ed25519Address.toHex()}`);

  const secp256k1Key = Secp256k1PrivateKey.fromMnemonic(mnemonic, 1n, "");
  const secp256k1Bech32 = secp256k1Key.toBech32();
  const secp256k1PubKey = secp256k1Key.publicKey();
  const secp256k1FlaggedPubKey = secp256k1PubKey.toFlaggedBytes();
  const secp256k1Address = secp256k1PubKey.deriveAddress();

  console.log("\nSecp256k1\n---");
  console.log(`Private Key: ${secp256k1Bech32}`);
  console.log(`Public Key: ${base64Encode(secp256k1PubKey.toBytes())}`);
  console.log(`Public Key With Flag: ${base64Encode(secp256k1FlaggedPubKey)}`);
  console.log(`Address: ${secp256k1Address.toHex()}`);

  const secp256r1Key = Secp256r1PrivateKey.fromMnemonicWithPath(mnemonic, "m/74'/4218'/0'/0/2", "");
  const secp256r1Bech32 = secp256r1Key.toBech32();
  const secp256r1PubKey = secp256r1Key.publicKey();
  const secp256r1FlaggedPubKey = secp256r1PubKey.toFlaggedBytes();
  const secp256r1Address = secp256r1PubKey.deriveAddress();

  console.log("\nSecp256r1\n---");
  console.log(`Private Key: ${secp256r1Bech32}`);
  console.log(`Public Key: ${base64Encode(secp256r1PubKey.toBytes())}`);
  console.log(`Public Key With Flag: ${base64Encode(secp256r1FlaggedPubKey)}`);
  console.log(`Address: ${secp256r1Address.toHex()}`);
}

main();
