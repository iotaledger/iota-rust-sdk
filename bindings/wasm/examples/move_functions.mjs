// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { Address, GraphQlClient, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const packageAddress = Address.fromHex(
  "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d",
);

const pkg = await client.package_(packageAddress);
if (pkg === null) {
  throw new Error("missing package");
}

for (const moduleId of pkg.modules().keys()) {
  const module = await client.normalizedMoveModule(
    packageAddress,
    moduleId.asStr(),
  );
  if (module === null) {
    console.log(`module \`${moduleId.asStr()}\` not found`);
    break;
  }
  if (module.functions !== null) {
    console.log(`Module: ${moduleId.asStr()}`);
    for (const fun of module.functions.nodes) {
      console.log(`- ${fun}`);
    }
    console.log();
  }
}
