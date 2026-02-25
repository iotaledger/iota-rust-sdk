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

        var sharedObjId = ObjectId.FromHex("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342");

        var transactions = await client.Transactions(filter: new TransactionsFilter(inputObject: sharedObjId));

        foreach (var transaction in transactions.data)
        {
            Console.WriteLine($"Digest: {transaction.transaction.Digest().ToBase58()}");
        }
    }
}
