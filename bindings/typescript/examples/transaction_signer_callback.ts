// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlClient,
  Address,
  TransactionBuilder,
  TransactionSigner,
  TransactionSignerFn,
  TransactionSignerFnOutput,
  Ed25519PrivateKey,
  PtbArgument,
  FaucetClient,
  hexEncode,
  Transaction,
  WaitForTx,
} from "../lib";

class AsyncSigner implements TransactionSignerFn {
  private key: Ed25519PrivateKey;

  constructor(key: Ed25519PrivateKey) {
    this.key = key;
  }

  async sign(transaction: Transaction): Promise<TransactionSignerFnOutput> {
    return TransactionSignerFnOutput.create({
      signature: this.key.signTransaction(transaction),
    });
  }
}

async function main() {
  const amount = 1000n;
  const recipientAddress = Address.fromHex(
    "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
  );

  const privateKey = new Ed25519PrivateKey(new Uint8Array(32));
  const publicKey = privateKey.publicKey();
  const senderAddress = publicKey.deriveAddress();
  console.log(`Sender address: ${senderAddress.toHex()}`);

  const client = GraphQlClient.newLocalnet();

  // Request funds from faucet
  const faucet = FaucetClient.newLocalnet();
  await faucet.requestAndWaitForFinalized(senderAddress, client);

  const builder = new TransactionBuilder(senderAddress).withClient(client);
  builder.sendIota(recipientAddress, PtbArgument.u64(amount));

  const signer = new TransactionSigner(new AsyncSigner(privateKey));
  const effects = await builder.execute(signer, "finalized");

  console.log(`Digest: ${hexEncode(effects.digest().toBytes())}`);
  console.log(`Transaction status: ${effects.asV1().status}`);
  console.log(`Effects: ${effects.asV1()}`);
}

main();
