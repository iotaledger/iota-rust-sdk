// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var transactions = await client.Transactions();
        if (transactions.Data.Length == 0)
        {
            throw new Exception("No transactions found");
        }
        var digest = transactions.Data[0].Transaction.Digest();

        var signedTransaction = await client.Transaction(digest);
        Console.WriteLine($"Signed Transaction: `{signedTransaction}`\n");

        var transactionEffects = await client.TransactionEffects(digest);
        Console.WriteLine($"Transaction Effects: `{transactionEffects}`\n");

        var transactionDataEffects = await client.TransactionDataEffects(digest);
        Console.WriteLine($"Transaction Data Effects: `{transactionDataEffects}`\n");
    }
}
