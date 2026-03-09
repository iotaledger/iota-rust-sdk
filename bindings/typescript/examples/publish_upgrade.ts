// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example allows you to publish any Move package by compiling it
// first using the `iota` binary. For demonstration purposes this example
// immediately upgrades the package after publishing it.
//
// ```bash
// cd /path/to/your/move/package
// export COMPILED_PACKAGE=$(iota move build --dump-bytecode-as-base64)
// ```
//
// With this example it is necessary to run a localnet:
//
// ```sh
// iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis
// ```

import {
  GraphQlClient,
  Address,
  TransactionBuilder,
  TransactionSigner,
  Ed25519PrivateKey,
  PtbArgument,
  Identifier,
  FaucetClient,
  MovePackageData,
  StructTag,
  UpgradePolicy,
  WaitForTx,
} from "../lib";

const PRECOMPILED_PACKAGE =
  '{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}';

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  // Read and parse the compiled package, or use the default package
  let packageDataJson = process.env.COMPILED_PACKAGE;
  if (!packageDataJson) {
    console.log("No compiled package found in env var. Using default.");
    packageDataJson = PRECOMPILED_PACKAGE;
  } else {
    console.log("Using custom Move package found in env var.");
  }

  const packageData = MovePackageData.fromJson(packageDataJson);
  const modules = packageData.modules();
  console.log(`Modules: ${modules.length}`);
  const dependencies = packageData.dependencies();
  console.log(`Dependencies: ${dependencies.length}`);
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
  if (faucetReceipt === undefined) {
    throw new Error("Failed to request coins from faucet");
  }

  // Build the `publish` PTB
  let builder = new TransactionBuilder(sender).withClient(client);
  // Publish the package and receive the upgrade cap in return
  builder.publish(packageData, "upgrade_cap");
  // Transfer the upgrade cap to the sender address
  builder.transferObjects(sender, [PtbArgument.assigned("upgrade_cap")]);
  let tx = await builder.finish();

  // Perform a dry-run first to check if everything is correct
  console.log("> Publishing package (dry run):");
  let result = await client.dryRunTx(tx, false);
  if (result.error !== undefined) {
    throw new Error(`Dry run failed: ${result.error}`);
  }
  if (result.effects === undefined) {
    throw new Error("Dry run failed: no effects");
  }
  console.log("Success");

  // Sign and execute the transaction (publish the package)
  console.log("> Publishing package:");
  let sig = privateKey.signTransaction(tx);
  let effects = await client.executeTx([sig], tx, "finalized");
  console.log("Success");

  // Wait some time for the indexer to process the tx
  await sleep(3000);

  // Resolve UpgradeCap and PackageId via the client
  let upgradeCap: any = null;
  let packageId: any = null;
  for (const changedObj of effects.asV1().changedObjects) {
    if (changedObj.outputState.tag === "objectWrite") {
      const objectId = changedObj.objectId;
      const obj = await client.object(objectId, undefined);
      if (obj === undefined) {
        throw new Error(`Missing object ${objectId.toHex()}`);
      }
      if (String(obj.asStruct().structType) === String(StructTag.newUpgradeCap())) {
        console.log(`UpgradeCap: ${objectId.toHex()}`);
        console.log(`UpgradeCapOwner: ${changedObj.outputState.inner.owner.asAddress().toHex()}`);
        upgradeCap = objectId;
      }
    } else if (changedObj.outputState.tag === "packageWrite") {
      packageId = changedObj.objectId;
      console.log(`Package ID: ${packageId.toHex()}`);
      const version = changedObj.outputState.inner.version;
      console.log(`Package version: ${version}`);
    }
  }

  if (upgradeCap === undefined) {
    throw new Error("Missing upgrade cap");
  }
  if (packageId === undefined) {
    throw new Error("Missing package id");
  }

  // Build the `upgrade` PTB
  builder = new TransactionBuilder(sender).withClient(client);

  // Authorize the upgrade by providing the upgrade cap object id to receive an upgrade
  // ticket
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
  builder.upgrade(packageId, packageData, PtbArgument.assigned("upgrade_ticket"), "upgrade_receipt");

  // Commit the upgrade using the receipt
  builder.moveCall(
    Address.framework(),
    new Identifier("package"),
    new Identifier("commit_upgrade"),
    [PtbArgument.objectId(upgradeCap), PtbArgument.assigned("upgrade_receipt")],
    [],
    [],
  );

  tx = await builder.finish();

  // Perform a dry-run first to check if everything is correct
  console.log("> Upgrading package (dry run):");
  result = await client.dryRunTx(tx, false);
  if (result.error !== undefined) {
    throw new Error(`Dry run failed: ${result.error}`);
  }
  if (result.effects === undefined) {
    throw new Error("Dry run failed: no effects");
  }
  console.log("Success");

  // Sign and execute the transaction (upgrade the package)
  console.log("> Upgrading package:");
  sig = privateKey.signTransaction(tx);
  effects = await client.executeTx([sig], tx);
  console.log("Success");

  // Wait some time for the indexer to process the tx
  await sleep(3000);

  // Print the new package version (should now be 2)
  for (const changedObj of effects.asV1().changedObjects) {
    if (changedObj.outputState.tag === "packageWrite") {
      console.log(`New Package ID: ${changedObj.objectId.toHex()}`);
      console.log(`New Package version: ${changedObj.outputState.inner.version}`);
    }
  }
}

main();
