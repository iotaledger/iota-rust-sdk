// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Send IOTA from a Ledger device's address on a local network, reaching the
// device through a transport implemented in JavaScript. The transport here
// talks to the Speculos emulator; in a browser, pass the APDUs to a WebHID or
// WebUSB transport instead.

import { createConnection } from "node:net";

import {
  Address,
  FaucetClient,
  GraphQlClient,
  initAsync,
  Ledger,
  PtbArgument,
  TransactionSigner,
  WaitForTransaction,
} from "@iota/sdk-wasm";

await initAsync();

// Exchanges APDUs with the APDU port of a Speculos emulator over TCP, one
// connection per exchange.
class SpeculosTransport {
  constructor(host, port) {
    this.host = host;
    this.port = port;
  }

  // Receives the APDU command and returns the answer with its status word,
  // both as an `ArrayBuffer`. An error thrown here fails the `Ledger` call
  // with its message.
  async exchange(apdu) {
    const socket = createConnection({ host: this.host, port: this.port });
    try {
      // Both directions are prefixed with the payload length as a 32-bit
      // big-endian integer; the answer length excludes its status word.
      const length = Buffer.alloc(4);
      length.writeUInt32BE(apdu.byteLength);
      socket.write(Buffer.concat([length, Buffer.from(apdu)]));

      let received = Buffer.alloc(0);
      for await (const chunk of socket) {
        received = Buffer.concat([received, chunk]);
        if (received.length < 4) continue;
        const end = 4 + received.readUInt32BE() + 2;
        if (received.length >= end) {
          return new Uint8Array(received.subarray(4, end)).buffer;
        }
      }
      throw new Error("Speculos closed the connection before answering");
    } finally {
      socket.destroy();
    }
  }
}

// Amount to send in nanos
const amount = 1000n;
const recipientAddress = Address.fromHex(
  "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
);

// Speculos runs the IOTA app alone; on a device, call `ledger.openApp()` first
const ledger = Ledger.fromTransport(new SpeculosTransport("127.0.0.1", 9999));
const signer = await ledger.signer("m/44'/4218'/0'/0'/0'");
const senderAddress = signer.address();
console.log(`Sender address: ${senderAddress}`);

const client = GraphQlClient.newLocalnet();

// Request funds from faucet
const faucet = FaucetClient.newLocalnet();
await faucet.requestAndWaitForFinalized(senderAddress, client);

const builder = client.transactionBuilder(senderAddress);
builder.sendIota(recipientAddress, PtbArgument.u64(amount));

// The builder passes the signer the coins the transaction spends, so the
// device shows the transfer instead of asking to blind-sign
console.log("Review and approve the transaction on the device");
const effects = await builder.execute(
  TransactionSigner.fromLedger(signer),
  WaitForTransaction.Finalized,
);
console.log(`Digest: ${effects.digest().toBase58()}`);
console.log(`Transaction status: ${effects.asV1().status().tag}`);
