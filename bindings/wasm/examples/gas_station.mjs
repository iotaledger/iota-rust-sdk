// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  Ed25519PrivateKey,
  GraphQlClient,
  Identifier,
  PtbArgument,
  TransactionBuilder,
  TransactionSigner,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newLocalnet();
const gasStationUrl = "http://0.0.0.0:9527";
const gasStationAuthToken = "test";
const keypair = Ed25519PrivateKey.random();
const sender = keypair.publicKey().deriveAddress();
const signer = TransactionSigner.fromEd25519(keypair);

const builder = new TransactionBuilder(sender).withClient(client);

builder.moveCall(Address.std(), new Identifier("u64"), new Identifier("sqrt"), [
  PtbArgument.u64(64n),
]);

builder.gasStationSponsor(
  gasStationUrl,
  undefined,
  new Map([["Authorization", [`Bearer ${gasStationAuthToken}`]]]),
);

const res = await builder.execute(signer);

console.log(res);
console.log("Sponsored transaction was successful!");
