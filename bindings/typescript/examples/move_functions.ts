// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Address } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();

  const packageAddress = Address.fromHex(
    "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d",
  );

  const pkg = await client.package_(packageAddress, undefined);
  if (pkg === undefined) {
    throw new Error("missing package");
  }

  for (const [moduleId] of pkg.modules()) {
    const mod = await client.normalizedMoveModule(packageAddress, moduleId.asStr());
    if (mod === undefined) {
      console.log(`module \`${moduleId.asStr()}\` not found`);
      return;
    }
    if (mod.functions !== undefined) {
      console.log(`Module: ${moduleId.asStr()}`);
      for (const fun of mod.functions.nodes) {
        console.log(`- ${String(fun)}`);
      }
      console.log();
    }
  }
}

main();
