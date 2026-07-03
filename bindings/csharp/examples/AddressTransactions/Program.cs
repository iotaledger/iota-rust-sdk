// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Fetch all transactions for an address (outgoing and incoming).
//
// The GraphQL service does not have a single filter that returns transactions
// in both directions for an address. To get the full history, run two queries
// and merge the results.

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();
        var address = Address.FromHex("0xa7c2cf9d8f8d95ff69d7a598c49c77acc36253f496f064a533ad306879b40bfa");

        var outgoing = await client.Transactions(filter: new TransactionsFilter(SentAddress: address));
        var incoming = await client.Transactions(filter: new TransactionsFilter(RecvAddress: address));

        Console.WriteLine($"Transactions for {address.ToHex()}");

        Console.WriteLine($"\nOutgoing (sent by address): {outgoing.Data.Length}");
        foreach (var tx in outgoing.Data)
        {
            Console.WriteLine($"  - {tx.Transaction.Digest().ToBase58()}");
        }

        Console.WriteLine($"\nIncoming (received by address): {incoming.Data.Length}");
        foreach (var tx in incoming.Data)
        {
            Console.WriteLine($"  - {tx.Transaction.Digest().ToBase58()}");
        }
    }
}
