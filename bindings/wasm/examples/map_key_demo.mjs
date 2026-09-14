// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// The same demo as on develop, against the map-object API: lookups now hit.
// Offline: the package is built locally, no node is involved.

import {
  Identifier,
  LinkageTable,
  MovePackage,
  ObjectId,
  PackageModules,
  Version,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const OBJECT_ID =
  "0x0000000000000000000000000000000000000000000000000000000000000002";

const coin = new Identifier("coin");

// Building the package now goes through the map objects.
const modules = new PackageModules([
  { key: coin, value: new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer },
]);
const pkg = new MovePackage(
  ObjectId.fromHex(OBJECT_ID),
  Version.fromU64(1n),
  modules,
  [],
  new LinkageTable([]),
);

const returned = pkg.modules();

console.log(`modules returned: ${returned.len()}`);
for (const entry of returned.entries()) {
  const hex = [...new Uint8Array(entry.value)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  console.log(`  iterated: "${entry.key.asStr()}" -> ${hex}`);
}

console.log(
  `\nlookup with the key we passed in:      ${returned.get(coin) !== undefined}`,
);
console.log(
  `lookup with an equal key:              ${returned.get(new Identifier("coin")) !== undefined}`,
);
console.log(
  `key from one call, looked up in next:  ${pkg.modules().containsKey(returned.keys()[0])}`,
);

console.log(
  "\nLookup runs in Rust against the key's Eq/Hash, so it works everywhere.",
);
