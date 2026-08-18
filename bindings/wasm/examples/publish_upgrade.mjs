// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// Publishes any Move package compiled with `iota` and then immediately upgrades
// it. Set the `COMPILED_PACKAGE` env var to the base64-encoded output of
// `iota move build --dump-bytecode-as-base64`, or run with no env var to use
// the default precompiled package below.
//
// Requires a running localnet:
//   iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis

import {
  Address,
  Ed25519PrivateKey,
  FaucetClient,
  GraphQlClient,
  Identifier,
  MovePackageData,
  PtbArgument,
  StructTag,
  TransactionBuilder,
  initAsync,
  UpgradePolicy,
  WaitForTx,
} from "@iota/sdk-wasm";

await initAsync();

const PRECOMPILED_PACKAGE =
  '{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}';

// Read and parse the compiled package
const packageDataJson = process.env.COMPILED_PACKAGE ?? PRECOMPILED_PACKAGE;
if (process.env.COMPILED_PACKAGE) {
  console.log("Using custom Move package found in env var.");
} else {
  console.log("No compiled package found in env var. Using default.");
}

const packageData = MovePackageData.fromJson(packageDataJson);
console.log(`Modules: ${packageData.modules().length}`);
console.log(`Dependencies: ${packageData.dependencies().length}`);
const digest = packageData.digest();
console.log(`Digest: ${digest.toBase58()}`);

// Create a random private key to derive a sender address and for signing
const privateKey = Ed25519PrivateKey.generate();
const sender = privateKey.publicKey().deriveAddress();
console.log(`Sender: ${sender.toHex()}`);

const client = GraphQlClient.newLocalnet();

// Fund the sender address for gas payment
const faucet = FaucetClient.newLocalnet();
const faucetReceipt = await faucet.requestAndWaitForFinalized(sender, client);
if (faucetReceipt === null) {
  throw new Error("Failed to request coins from faucet");
}

// Build the `publish` PTB
let builder = new TransactionBuilder(sender).withClient(client);
// Publish the package and receive the upgrade cap
builder.publishPackage(packageData, "upgrade_cap");
// Transfer the upgrade cap to the sender address
builder.transferObjects(sender, [PtbArgument.assigned("upgrade_cap")]);
let tx = await builder.finish();

// Perform a dry-run first to check if everything is correct
console.log("> Publishing package (dry run):");
let result = await client.dryRunTx(tx, false);
if (result.error) throw new Error(`Dry run failed: ${result.error}`);
if (result.effects === null) throw new Error("Dry run failed: no effects");
console.log("Success");

// Sign and execute the transaction (publish the package)
console.log("> Publishing package:");
let sig = privateKey.signTransaction(tx);
let effects = await client.executeTx([sig], tx, WaitForTx.Finalized);
console.log("Success");

// Resolve UpgradeCap and PackageId via the client
let upgradeCap = null;
let packageId = null;
for (const changedObj of effects.asV1().changedObjects) {
  if (changedObj.outputState.tag === "ObjectWrite") {
    const objectId = changedObj.objectId;
    const obj = await client.object(objectId);
    if (obj === null) throw new Error(`Missing object ${objectId.toHex()}`);
    if (obj.asStruct().structType.equals(StructTag.newUpgradeCap())) {
      console.log(`UpgradeCap: ${objectId.toHex()}`);
      console.log(
        `UpgradeCapOwner: ${changedObj.outputState.inner.owner.asAddress().toHex()}`,
      );
      upgradeCap = objectId;
    }
  } else if (changedObj.outputState.tag === "PackageWrite") {
    packageId = changedObj.objectId;
    console.log(`Package ID: ${packageId.toHex()}`);
    console.log(`Package version: ${changedObj.outputState.inner.version}`);
  }
}

if (upgradeCap === null) throw new Error("Missing upgrade cap");
if (packageId === null) throw new Error("Missing package id");

// Build the `upgrade` PTB
builder = new TransactionBuilder(sender).withClient(client);
// Authorize the upgrade by providing the upgrade cap object id to receive an
// upgrade ticket
builder.moveCall(
  Address.framework(),
  new Identifier("package"),
  new Identifier("authorize_upgrade"),
  [
    PtbArgument.objectId(upgradeCap),
    PtbArgument.u8(UpgradePolicy.compatible().asU8()),
    PtbArgument.u8Vec(digest.toBytes()),
  ],
  [],
  ["upgrade_ticket"],
);
// Upgrade the package to receive an upgrade receipt
builder.upgrade(
  packageId,
  packageData,
  PtbArgument.assigned("upgrade_ticket"),
  "upgrade_receipt",
);
// Commit the upgrade using the receipt
builder.moveCall(
  Address.framework(),
  new Identifier("package"),
  new Identifier("commit_upgrade"),
  [PtbArgument.objectId(upgradeCap), PtbArgument.assigned("upgrade_receipt")],
);

tx = await builder.finish();

// Perform a dry-run first to check if everything is correct
console.log("> Upgrading package (dry run):");
result = await client.dryRunTx(tx, false);
if (result.error) throw new Error(`Dry run failed: ${result.error}`);
if (result.effects === null) throw new Error("Dry run failed: no effects");
console.log("Success");

// Sign and execute the transaction (upgrade the package)
console.log("> Upgrading package:");
sig = privateKey.signTransaction(tx);
effects = await client.executeTx([sig], tx);
console.log("Success");

// Print the new package version (should now be 2)
for (const changedObj of effects.asV1().changedObjects) {
  if (changedObj.outputState.tag === "PackageWrite") {
    console.log(`New Package ID: ${changedObj.objectId.toHex()}`);
    console.log(`New Package version: ${changedObj.outputState.inner.version}`);
  }
}
