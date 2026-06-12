// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  GraphQlClient,
  Identifier,
  ObjectId,
  PtbArgument,
  StructTag,
  TransactionBuilder,
  TypeTag,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();
const sender = Address.zero();

const iotaNamesPackageAddress = Address.fromHex(
  "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea",
);
const iotaNamesObjectId = ObjectId.fromHex(
  "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec",
);
const stdAddress = Address.std();

const name = "name.iota";
console.log(`Looking up name: ${name}`);

const builder = new TransactionBuilder(sender).withClient(client);

// 1. Get the registry
builder.moveCall(
  iotaNamesPackageAddress,
  new Identifier("iota_names"),
  new Identifier("registry"),
  [PtbArgument.sharedMut(iotaNamesObjectId)],
  [
    TypeTag.newStruct(
      new StructTag(
        iotaNamesPackageAddress,
        new Identifier("registry"),
        new Identifier("Registry"),
      ),
    ),
  ],
  ["iota_names"],
);

// 2. Create name from string
builder.moveCall(
  iotaNamesPackageAddress,
  new Identifier("name"),
  new Identifier("new"),
  [PtbArgument.string(name)],
  [],
  ["name"],
);

// 3. Lookup name record
builder.moveCall(
  iotaNamesPackageAddress,
  new Identifier("registry"),
  new Identifier("lookup"),
  [PtbArgument.assigned("iota_names"), PtbArgument.assigned("name")],
  [],
  ["name_record_opt"],
);

// 4. Borrow name record from option
builder.moveCall(
  stdAddress,
  new Identifier("option"),
  new Identifier("borrow"),
  [PtbArgument.assigned("name_record_opt")],
  [
    TypeTag.newStruct(
      new StructTag(
        iotaNamesPackageAddress,
        new Identifier("name_record"),
        new Identifier("NameRecord"),
      ),
    ),
  ],
  ["name_record"],
);

// 5. Get target address from name record
builder.moveCall(
  iotaNamesPackageAddress,
  new Identifier("name_record"),
  new Identifier("target_address"),
  [PtbArgument.assigned("name_record")],
  [],
  ["target_address_opt"],
);

// 6. Borrow address from option
builder.moveCall(
  stdAddress,
  new Identifier("option"),
  new Identifier("borrow"),
  [PtbArgument.assigned("target_address_opt")],
  [TypeTag.newAddress()],
  ["target_address"],
);

const res = await builder.dryRun(true);
if (res.error) {
  throw new Error(`Failed to lookup name: ${res.error}`);
}

// Extract the resolved address from the last result
if (res.results.length > 0) {
  const lastEffect = res.results[res.results.length - 1];
  if (lastEffect.returnValues.length > 0) {
    const returnValue = lastEffect.returnValues[0];
    if (returnValue.typeTag.isAddress() && returnValue.bcs.length === 32) {
      const resolvedAddress = Address.fromBytes(returnValue.bcs);
      console.log(`Resolved address: ${resolvedAddress.toHex()}`);
    } else {
      console.log(
        `Last result is not an address type or has wrong length: ${returnValue.bcs.length}`,
      );
    }
  } else {
    console.log("No return value in last effect");
  }
} else {
  console.log("No results found");
}
