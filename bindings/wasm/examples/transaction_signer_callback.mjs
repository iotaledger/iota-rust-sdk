// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  Ed25519PrivateKey,
  FaucetClient,
  GraphQlClient,
  hexEncode,
  PtbArgument,
  TransactionSigner,
  TransactionSignerFnOutput,
  initAsync,
  WaitForTransaction,
} from "@iota/sdk-wasm";

await initAsync();

// A signer implemented in the host language. This one wraps a local key, which
// needs nothing but the transaction, so it opts out of the objects the builder
// fetches for a signer that shows the transaction to its user, such as a
// hardware wallet.
class AsyncSigner {
  constructor(key) {
    this.key = key;
  }

  async sign(transaction) {
    return TransactionSignerFnOutput.new({
      signature: this.key.signTransaction(transaction),
    });
  }

  usesObjects() {
    return false;
  }

  // Never called for a signer whose `usesObjects` returns false; the
  // interface still requires it.
  async signWithObjects(transaction, objects) {
    return this.sign(transaction);
  }
}

const amount = 1000n;
const recipientAddress = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);

const privateKey = new Ed25519PrivateKey(new Uint8Array(32));
const publicKey = privateKey.publicKey();
const senderAddress = publicKey.deriveAddress();
console.log(`Sender address: ${senderAddress}`);

const client = GraphQlClient.newLocalnet();

// Request funds from faucet
const faucet = FaucetClient.newLocalnet();
await faucet.requestAndWaitForFinalized(senderAddress, client);

const builder = client.transactionBuilder(senderAddress);
builder.sendIota(recipientAddress, PtbArgument.u64(amount));

const signer = new TransactionSigner(new AsyncSigner(privateKey));
const effects = await builder.execute(signer, WaitForTransaction.Finalized);

console.log(`Digest: ${hexEncode(effects.digest().toBytes())}`);
console.log(`Transaction status: ${effects.asV1().status()}`);
console.log(`Effects: ${effects.asV1()}`);
