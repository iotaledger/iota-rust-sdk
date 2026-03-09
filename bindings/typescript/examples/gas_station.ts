// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlClient,
  Address,
  TransactionBuilder,
  TransactionSigner,
  Ed25519PrivateKey,
  Identifier,
  PtbArgument,
} from "../lib";

async function main() {
  const client = GraphQlClient.newLocalnet();
  const gasStationUrl = "http://0.0.0.0:9527";
  const gasStationAuthToken = "test";
  const keypair = Ed25519PrivateKey.generate();
  const sender = keypair.publicKey().deriveAddress();
  const signer = TransactionSigner.fromEd25519(keypair);

  const builder = new TransactionBuilder(sender).withClient(client);

  builder.moveCall(Address.std(), new Identifier("u64"), new Identifier("sqrt"), [
    PtbArgument.u64(64n),
  ], [], []);

  const headers = new Map<string, Array<string>>();
  headers.set("Authorization", [`Bearer ${gasStationAuthToken}`]);
  builder.gasStationSponsor(gasStationUrl, undefined, headers);

  const res = await builder.execute(signer);

  console.log(res);

  console.log("Sponsored transaction was successful!");
}

main();
