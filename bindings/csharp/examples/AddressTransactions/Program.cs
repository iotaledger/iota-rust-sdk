// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Fetch all transactions for an address (outgoing and incoming).
//
// The GraphQL service does not have a single filter that returns transactions
// in both directions for an address. To get the full history, run two queries
// and merge the results:
//   * signAddress -> transactions sent by the address (outgoing,
//                    equivalent to GraphQL's `relation: SENT`).
//   * recvAddress -> transactions that transferred objects to the address
//                    (incoming, equivalent to GraphQL's `relation: RECV`).
//
// Omitting both filters effectively returns sent-only, so an address that has
// only ever received coins will appear to have no history unless recvAddress
// is set.

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();
        var address = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        var outgoing = await client.Transactions(filter: new TransactionsFilter(signAddress: address));
        var incoming = await client.Transactions(filter: new TransactionsFilter(recvAddress: address));

        Console.WriteLine($"Transactions for {address.ToHex()}");

        Console.WriteLine($"\nOutgoing (sent by address): {outgoing.data.Count}");
        foreach (var tx in outgoing.data)
        {
            Console.WriteLine($"  - {tx.transaction.Digest().ToBase58()}");
        }

        Console.WriteLine($"\nIncoming (received by address): {incoming.data.Count}");
        foreach (var tx in incoming.data)
        {
            Console.WriteLine($"  - {tx.transaction.Digest().ToBase58()}");
        }
    }
}
