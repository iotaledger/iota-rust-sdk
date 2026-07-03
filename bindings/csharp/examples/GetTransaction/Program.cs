// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();
        var digest = TransactionDigest.FromBase58("3wN9oLKfvCjCd7uFW1D6fp1uSEsD3wJ2cU61YULNKzFh");

        var signedTransaction = await client.Transaction(digest);
        Console.WriteLine($"Signed Transaction: `{signedTransaction}`\n");

        var transactionEffects = await client.TransactionEffects(digest);
        Console.WriteLine($"Transaction Effects: `{transactionEffects}`\n");

        var transactionDataEffects = await client.TransactionDataEffects(digest);
        Console.WriteLine($"Transaction Data Effects: `{transactionDataEffects}`\n");
    }
}
