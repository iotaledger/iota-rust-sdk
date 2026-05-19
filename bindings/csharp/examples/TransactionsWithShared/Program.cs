// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        // The IOTA system state object (0x5) is a well-known shared object that is
        // present on every network including localnet.
        var sharedObjId = ObjectId.SystemState();

        var transactions = await client.Transactions(filter: new TransactionsFilter(inputObject: sharedObjId));

        foreach (var transaction in transactions.data)
        {
            Console.WriteLine($"Digest: {transaction.transaction.Digest().ToBase58()}");
        }
    }
}
