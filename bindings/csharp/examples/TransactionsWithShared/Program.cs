// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var sharedObjId = ObjectId.FromHex("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec");

        var transactions = await client.Transactions(filter: new TransactionsFilter(InputObject: sharedObjId));

        foreach (var transaction in transactions.Data)
        {
            Console.WriteLine($"Digest: {transaction.Transaction.Digest().ToBase58()}");
        }
    }
}
