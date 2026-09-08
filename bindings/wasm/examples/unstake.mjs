// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Ed25519PrivateKey,
  FaucetClient,
  GraphQlClient,
  ObjectFilter,
  PtbArgument,
  StructTag,
  UserSignature,
  WaitForTransaction,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newLocalnet();

const privateKey = Ed25519PrivateKey.random();
const owner = privateKey.publicKey().deriveAddress();

const faucet = FaucetClient.newLocalnet();
await faucet.requestAndWaitForFinalized(owner, client);

// Stake to get a StakedIota object that can be unstaked
const validators = await client.activeValidators();
if (validators.data.length === 0) {
  throw new Error("no validators found");
}
const stakeBuilder = client.transactionBuilder(owner);
stakeBuilder.stake(PtbArgument.u64(1000000000n), validators.data[0].address);
const stakeTx = await stakeBuilder.finish();
const signature = privateKey.trySignSimple(stakeTx.signingDigest());
await client.executeTransaction(
  [UserSignature.newSimple(signature)],
  stakeTx,
  WaitForTransaction.Finalized,
);

// Unstake
const stakedIotas = await client.objects(
  ObjectFilter.new({ typeTag: String(StructTag.newStakedIota()), owner }),
);
if (stakedIotas.data.length === 0) {
  throw new Error("no staked iotas found");
}
const stakedIota = stakedIotas.data[0];

const builder = client.transactionBuilder(stakedIota.owner().asAddress());

builder.unstake(PtbArgument.objectId(stakedIota.id()));

const res = await builder.dryRun();
if (res.error) {
  throw new Error(`Failed to unstake: ${res.error}`);
}

console.log("Unstake dry run was successful!");
