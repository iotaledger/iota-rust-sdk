// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// This example inspects a published Move package on testnet and prints its
// upgrade policy, version history, dependencies, functions, types, and sample
// objects.

import {
  Address,
  Direction,
  GraphQlClient,
  MoveAbility,
  ObjectFilter,
  PaginationFilter,
  StructTag,
  TransactionsFilter,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const FRAMEWORK_PACKAGE_ID = Address.framework().toHex();
const HEX_DIGITS = new Set("0123456789abcdefABCDEF");

function forwardPage(cursor = undefined) {
  return PaginationFilter.new({ direction: Direction.Forward, cursor });
}

function shortenPackageIds(signature) {
  const parts = [];
  let index = 0;
  while (index < signature.length) {
    if (signature.startsWith("0x", index)) {
      let end = index + 2;
      while (end < signature.length && HEX_DIGITS.has(signature[end])) {
        end += 1;
      }
      if (end > index + 2) {
        const candidate = signature.slice(index, end);
        try {
          parts.push(Address.fromHex(candidate).toShortHex());
          index = end;
          continue;
        } catch {
          parts.push(candidate);
          index = end;
          continue;
        }
      }
    }
    parts.push(signature[index]);
    index += 1;
  }
  return parts.join("");
}

function formatFunctionSignature(signature, packagePrefix) {
  return shortenPackageIds(signature.replaceAll(`${packagePrefix}::`, ""));
}

async function fetchPackageVersions(client, packageAddress) {
  const versions = [];
  let cursor = undefined;
  while (true) {
    const page = await client.packageVersions(
      packageAddress,
      undefined,
      undefined,
      forwardPage(cursor),
    );
    versions.push(...page.data);
    if (page.pageInfo.hasNextPage) {
      cursor = page.pageInfo.endCursor;
    } else {
      break;
    }
  }
  versions.sort((a, b) => Number(a.version().asU64() - b.version().asU64()));
  return versions;
}

async function printObjectSamples(client, typeTag, hasKeyAbility, isGeneric) {
  if (!hasKeyAbility) return;
  if (isGeneric) {
    console.log("    sample objects: skipped for generic type");
    return;
  }
  const objects = await client.objects(
    ObjectFilter.new({ typeTag }),
    PaginationFilter.new({ direction: Direction.Forward, limit: 3 }),
  );
  if (objects.data.length === 0) {
    console.log("    sample objects: none found");
    return;
  }
  console.log("    sample objects:");
  for (const obj of objects.data) {
    console.log(
      `      - ${obj.id().toHex()} (version ${obj.version().asU64()})`,
    );
  }
  if (objects.pageInfo.hasNextPage) console.log("      - ...");
}

function formatPolicyName(policy) {
  return (
    { 0: "Compatible", 128: "Additive", 192: "Dependency-only" }[policy] ??
    `Unknown (${policy})`
  );
}

function extractPolicy(contents) {
  let parsed;
  try {
    parsed = JSON.parse(contents);
  } catch {
    return null;
  }
  const policy = parsed?.policy;
  if (typeof policy === "string")
    return /^\d+$/.test(policy) ? Number(policy) : null;
  if (typeof policy === "number") return policy;
  return null;
}

async function resolveUpgradeCapId(client, packageId) {
  const page = await client.transactionsEffects(
    TransactionsFilter.new({ changedObject: packageId }),
    PaginationFilter.new({ direction: Direction.Forward, limit: 1 }),
  );
  for (const effects of page.data) {
    const effectsV1 = effects.asV1();
    for (const changedObj of effectsV1.changedObjects()) {
      if (!changedObj.outputState.isObjectWrite()) continue;
      const obj = await client.object(
        changedObj.objectId,
        effectsV1.lamportVersion(),
      );
      if (obj !== null && obj.asStructOpt() !== null) {
        if (
          obj.asStruct().structType.eq?.(StructTag.newUpgradeCap()) ??
          false
        ) {
          return changedObj.objectId;
        }
      }
    }
  }
  return null;
}

function sameObjectId(left, right) {
  return typeof left === "string" && left.toLowerCase() === right.toLowerCase();
}

function programmableTransactionJson(tx) {
  let parsed;
  try {
    parsed = JSON.parse(tx.toJson());
  } catch {
    return null;
  }
  const txV1 = parsed?.["1"];
  if (typeof txV1 !== "object" || txV1 === null) return null;
  const kind = txV1.kind;
  if (typeof kind !== "object" || kind === null) return null;
  if (kind.kind !== "programmable_transaction") return null;
  return kind;
}

function isPackageMakeImmutableCall(command) {
  return (
    typeof command === "object" &&
    command !== null &&
    command.command === "move_call" &&
    sameObjectId(command.package, FRAMEWORK_PACKAGE_ID) &&
    command.module === "package" &&
    command.function === "make_immutable"
  );
}

function inputMatchesObjectId(input, objectId) {
  return (
    typeof input === "object" &&
    input !== null &&
    ["immutable_or_owned", "receiving", "shared"].includes(input.type) &&
    sameObjectId(input.object_id, objectId)
  );
}

function publishesPackageAsImmutable(tx) {
  const programmable = programmableTransactionJson(tx);
  if (programmable === null) return false;
  const commands = programmable.commands;
  if (!Array.isArray(commands)) return false;
  const publishIndexes = commands
    .map((c, i) => (typeof c === "object" && c?.command === "publish" ? i : -1))
    .filter((i) => i !== -1);
  if (publishIndexes.length !== 1) return false;
  const publishIndex = publishIndexes[0];
  for (const command of commands.slice(publishIndex + 1)) {
    if (!isPackageMakeImmutableCall(command)) continue;
    const args = command.arguments;
    if (
      Array.isArray(args) &&
      args.length === 1 &&
      typeof args[0] === "object" &&
      args[0]?.result === publishIndex
    ) {
      return true;
    }
  }
  return false;
}

function usesUpgradeCapForMakeImmutable(tx, upgradeCapId) {
  const programmable = programmableTransactionJson(tx);
  if (programmable === null) return false;
  const inputs = programmable.inputs;
  const commands = programmable.commands;
  if (!Array.isArray(inputs) || !Array.isArray(commands)) return false;
  const upgradeCapInputs = inputs
    .map((input, i) =>
      inputMatchesObjectId(input, upgradeCapId.toHex()) ? i : -1,
    )
    .filter((i) => i !== -1);
  if (upgradeCapInputs.length === 0) return false;
  for (const command of commands) {
    if (!isPackageMakeImmutableCall(command)) continue;
    const args = command.arguments;
    if (!Array.isArray(args) || args.length !== 1) continue;
    const arg = args[0];
    if (
      typeof arg === "object" &&
      arg !== null &&
      typeof arg.input === "number" &&
      upgradeCapInputs.includes(arg.input)
    ) {
      return true;
    }
  }
  return false;
}

async function wasPackagePublishedAsImmutable(client, packageId) {
  let cursor = undefined;
  while (true) {
    const page = await client.transactionsDataEffects(
      TransactionsFilter.new({ changedObject: packageId }),
      forwardPage(cursor),
    );
    for (const txData of page.data) {
      if (publishesPackageAsImmutable(txData.signedTransaction.transaction))
        return true;
    }
    if (page.pageInfo.hasNextPage) cursor = page.pageInfo.endCursor;
    else return false;
  }
}

async function wasUpgradeCapUsedForMakeImmutable(client, upgradeCapId) {
  let cursor = undefined;
  while (true) {
    const page = await client.transactionsDataEffects(
      TransactionsFilter.new({ inputObject: upgradeCapId }),
      forwardPage(cursor),
    );
    for (const txData of page.data) {
      if (
        usesUpgradeCapForMakeImmutable(
          txData.signedTransaction.transaction,
          upgradeCapId,
        )
      )
        return true;
    }
    if (page.pageInfo.hasNextPage) cursor = page.pageInfo.endCursor;
    else return false;
  }
}

async function currentPackagePolicy(client, packageId) {
  const upgradeCapId = await resolveUpgradeCapId(client, packageId);
  if (upgradeCapId === null) {
    if (await wasPackagePublishedAsImmutable(client, packageId))
      return "Immutable";
    return "Unavailable";
  }
  const contents = await client.moveObjectContents(upgradeCapId);
  if (contents === null) {
    if (await wasUpgradeCapUsedForMakeImmutable(client, upgradeCapId))
      return "Immutable";
    return "Unavailable";
  }
  const policy = extractPolicy(contents);
  return policy !== null ? formatPolicyName(policy) : "Unavailable";
}

const packageId =
  "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d";
const packageAddress = Address.fromHex(packageId);
const client = GraphQlClient.newTestnet();

// Fetch package metadata and version history.
const pkg = await client.package_(packageAddress);
if (pkg === null) throw new Error("missing package");

const latestPackage = await client.packageLatest(packageAddress);
if (latestPackage === null) throw new Error("missing latest package");

const versions = await fetchPackageVersions(client, packageAddress);
const packagePrefix = pkg.id().toHex();
console.log(
  `Latest version: ${latestPackage.version().asU64()} (${latestPackage.id().toHex()})`,
);
// Resolve the current upgrade policy.
console.log(
  `Current package policy: ${await currentPackagePolicy(client, pkg.id())}\n`,
);

// Print the package version history.
console.log("Versions:");
for (const version of versions) {
  const labels = [];
  if (version.id().eq?.(pkg.id()) ?? false) labels.push("requested");
  if (version.id().eq?.(latestPackage.id()) ?? false) labels.push("latest");
  let line = `- v${version.version().asU64()} -> ${version.id().toHex()}`;
  if (labels.length > 0) line += ` [${labels.join(", ")}]`;
  console.log(line);
}
console.log();

// Print package dependencies and their linked versions.
console.log("Dependencies:");
const linkageTable = pkg.linkageTable();
if (linkageTable.size === 0) {
  console.log("- none");
} else {
  const upgrades = [...linkageTable.values()].sort((a, b) =>
    a.upgradedId.toHex() < b.upgradedId.toHex() ? -1 : 1,
  );
  for (const upgrade of upgrades) {
    console.log(
      `- ${upgrade.upgradedId.toHex()} @ v${upgrade.upgradedVersion.asU64()}`,
    );
  }
}
console.log();

// Inspect normalized modules, functions, types, and sample key objects.
console.log("Package contents:");
const moduleNames = [...pkg.modules().keys()].map((m) => m.asStr()).sort();

for (const moduleName of moduleNames) {
  console.log(`Module: ${moduleName}`);
  const module = await client.normalizedMoveModule(
    packageAddress,
    moduleName,
    undefined,
    forwardPage(),
    forwardPage(),
    forwardPage(),
    forwardPage(),
  );
  if (module === null) {
    console.log("  metadata: missing\n");
    continue;
  }
  if (module.functions === null || module.functions.nodes.length === 0) {
    console.log("  functions: none");
  } else {
    console.log("  functions:");
    for (const fun of module.functions.nodes) {
      console.log(
        `    - ${formatFunctionSignature(String(fun), packagePrefix)}`,
      );
    }
    if (module.functions.pageInfo.hasNextPage) console.log("    - ...");
  }
  if (module.structs === null || module.structs.nodes.length === 0) {
    console.log("  types: none");
  } else {
    console.log("  types:");
    for (const struct_ of module.structs.nodes) {
      const typeTag = `${packagePrefix}::${moduleName}::${struct_.name}`;
      console.log(`    - ${typeTag}`);
      const hasKeyAbility =
        struct_.abilities !== null &&
        struct_.abilities.includes(MoveAbility.Key);
      const isGeneric =
        struct_.typeParameters !== null && struct_.typeParameters.length > 0;
      await printObjectSamples(client, typeTag, hasKeyAbility, isGeneric);
    }
    if (module.structs.pageInfo.hasNextPage) console.log("    - ...");
  }
  console.log();
}
