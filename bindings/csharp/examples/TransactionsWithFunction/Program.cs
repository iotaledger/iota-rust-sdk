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
        var transactions = await client.Transactions(filter: new TransactionsFilter(function: "0x3::iota_system::request_add_stake"));

        foreach (var transaction in transactions.data)
        {
            Console.WriteLine($"Digest: {transaction.transaction.Digest().ToBase58()}");
        }
    }
}
