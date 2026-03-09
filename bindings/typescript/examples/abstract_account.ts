// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlClient,
  Address,
  ObjectId,
  TransactionBuilder,
  TransactionSigner,
  Ed25519PrivateKey,
  PtbArgument,
  Identifier,
  FaucetClient,
  MovePackageData,
  MoveAuthenticatorBuilder,
  WaitForTx,
} from "../lib";

const PRECOMPILED_PACKAGE =
  '{"modules":["oRzrCwYAAAALAQAUAhQmAzorBGUGBWtPB7oBwAII+gNgBtoECRDjBCoKjQULDJgFQgAJAgkCCwINAg4CFgIXAhoCGwEKAAEMAAAAAgACAgIAAwMHAQgBBAQIAAUIBAAGBQgACAcCAAkGBwAAEwABAAAUAgEAAAwDAQABDwsBAQgDEAkKAQgFFQQFAAcYBwEBDAkZDA0ABgYEBgMGAggBBwgHAAQIAAYIBggICAgFBggACAgGCAQGCAIGCAcBBwgHAQgFAQgAAQkAAQsDAQgAAwYIBggICAgBCwMBCQACCQALAwEJAAEKAgEICAdBQ0NPVU5UB0FjY291bnQLQXV0aENvbnRleHQaQXV0aGVudGljYXRvckZ1bmN0aW9uUmVmVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlFmF1dGhlbnRpY2F0b3JfZnVuY3Rpb24FY2xvY2sRY3JlYXRlX2FjY291bnRfdjEbY3JlYXRlX2F1dGhfZnVuY3Rpb25fcmVmX3YxC2R1bW15X2ZpZWxkAmlkBGluaXQJbGlua19hdXRoA25ldwZvYmplY3QQcGFja2FnZV9tZXRhZGF0YRNwdWJsaWNfc2hhcmVfb2JqZWN0BnN0cmluZwh0cmFuc2Zlcgp0eF9jb250ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCgIGBWhlbGxvDmlvdGE6Om1ldGFkYXRhGgEAAAAAAAAAEQEMYXV0aGVudGljYXRlAQABAAIBEggFAQIBEQEAAAAAAQULAREFEgA4AAIBAQAACAkLAQsCCwM4AQwECwALBDgCAgIBAAABCQsBBwARByEEBgUIBgAAAAAAAAAAJwIA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[236,68,86,252,91,28,224,206,146,112,120,93,47,52,14,168,169,132,252,75,45,104,10,116,171,91,155,100,66,111,66,147]}';

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function setupAccount(client: GraphQlClient): Promise<ObjectId> {
  // Parse the precompiled move package
  const packageData = MovePackageData.fromJson(PRECOMPILED_PACKAGE);

  // Create a random private key to derive a sender address
  const privateKey = Ed25519PrivateKey.generate();
  const sender = privateKey.publicKey().deriveAddress();

  // Fund the sender address for gas payment
  const faucet = FaucetClient.newLocalnet();
  const faucetReceipt = await faucet.requestAndWaitForFinalized(sender, client);
  if (faucetReceipt === undefined) {
    throw new Error("Failed to request coins from faucet");
  }

  // Build the `publish` PTB
  let builder = new TransactionBuilder(sender).withClient(client);
  // Publish the package and receive the upgrade cap
  builder.publish(packageData, "upgrade_cap");
  // Transfer the upgrade cap to the sender address
  builder.transferObjects(sender, [PtbArgument.assigned("upgrade_cap")]);

  // Sign and execute the transaction (publish the package)
  const signer = TransactionSigner.fromEd25519(privateKey);
  let effects = await builder.execute(signer, "finalized");

  console.log(`Publishing package: ${effects.asV1().status}\n`);

  // Wait some time for the indexer to process the tx
  await sleep(3000);

  // Get package, package metadata and account IDs from the effects
  let packageId: ObjectId | null = null;
  let packageMetadataId: ObjectId | null = null;
  let accountId: ObjectId | null = null;

  for (const changedObj of effects.asV1().changedObjects) {
    if (changedObj.outputState.tag === "packageWrite") {
      packageId = changedObj.objectId;
    } else if (changedObj.outputState.tag === "objectWrite") {
      const objectId = changedObj.objectId;
      const obj = await client.object(objectId, undefined);

      if (obj !== undefined) {
        const typeName = obj.asStruct().structType.name().asStr();
        if (typeName === "PackageMetadataV1") {
          packageMetadataId = objectId;
        }
        if (typeName === "Account") {
          accountId = objectId;
        }
      }
    }
  }

  if (packageId === undefined) {
    throw new Error("Missing package id");
  }
  if (packageMetadataId === undefined) {
    throw new Error("Missing package metadata id");
  }
  if (accountId === undefined) {
    throw new Error("Missing account id");
  }

  console.log(`Package ID: ${packageId.toHex()}`);
  console.log(`PackageMetadataV1 ID: ${packageMetadataId.toHex()}`);
  console.log(`Account ID: ${accountId.toHex()}\n`);

  // Build the `link_auth` PTB
  builder = new TransactionBuilder(sender).withClient(client);
  builder.moveCall(packageId.toAddress(), new Identifier("account"), new Identifier("link_auth"), [
    PtbArgument.sharedMut(accountId),
    PtbArgument.objectId(packageMetadataId),
    PtbArgument.string("account"),
    PtbArgument.string("authenticate"),
  ], [], []);

  // Sign and execute the transaction (link the authenticator)
  effects = await builder.execute(signer, "finalized");

  console.log(`Linking account to authenticate method: ${effects.asV1().status}\n`);

  return accountId;
}

async function main() {
  const client = GraphQlClient.newLocalnet();
  const accountId = await setupAccount(client);
  const fromAddress = accountId.toAddress();
  const toAddress = Address.fromHex(
    "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
  );

  // Fund the sender address for gas payment
  const faucet = FaucetClient.newLocalnet();
  const faucetReceipt = await faucet.requestAndWaitForFinalized(fromAddress, client);
  if (faucetReceipt === undefined) {
    throw new Error("Failed to request coins from faucet");
  }

  const builder = new TransactionBuilder(fromAddress).withClient(client);
  builder.sendIota(toAddress, PtbArgument.u64(5000000000n));

  const moveAuthenticator = await new MoveAuthenticatorBuilder(
    accountId,
    [PtbArgument.string("hello"), PtbArgument.shared(ObjectId.clock())],
    [],
  ).finish(client);

  const signer = TransactionSigner.fromMoveAuthenticator(moveAuthenticator);
  const effects = await builder.execute(signer, "finalized");

  console.log(`Sending IOTA via abstract account: ${effects.asV1().status}`);
}

main();
