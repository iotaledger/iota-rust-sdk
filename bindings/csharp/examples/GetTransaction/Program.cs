// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Threading.Tasks;
using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();
        var digest = Digest.FromBase58("Agug2GETToZj4Ncw3RJn2KgDUEpVQKG1WaTZVcLcqYnf");

        var signedTransaction = await client.Transaction(digest);
        Console.WriteLine($"Signed Transaction: `{signedTransaction}`\n");

        var transactionEffects = await client.TransactionEffects(digest);
        Console.WriteLine($"Transaction Effects: `{transactionEffects}`\n");

        var transactionDataEffects = await client.TransactionDataEffects(digest);
        Console.WriteLine($"Transaction Data Effects: `{transactionDataEffects}`\n");
    }
}
