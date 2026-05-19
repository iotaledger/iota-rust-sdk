// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var latest = await client.Transactions();
        if (latest.data.Length == 0)
        {
            throw new Exception("no transactions available on the network");
        }
        var digest = latest.data[0].transaction.Digest();
        Console.WriteLine($"Querying transaction: {digest.ToBase58()}");

        var signedTransaction = await client.Transaction(digest);
        Console.WriteLine($"Signed Transaction: `{signedTransaction}`\n");

        var transactionEffects = await client.TransactionEffects(digest);
        Console.WriteLine($"Transaction Effects: `{transactionEffects}`\n");

        var transactionDataEffects = await client.TransactionDataEffects(digest);
        Console.WriteLine($"Transaction Data Effects: `{transactionDataEffects}`\n");
    }
}
