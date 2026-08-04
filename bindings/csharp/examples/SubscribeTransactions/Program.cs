// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Tail transactions as they are executed, over a GraphQL subscription.
//
// Unlike the paginated queries, a subscription never ends on its own: it is
// pulled one update at a time and stopped with Cancel. Localnet may be idle,
// so the example asks the faucet for coins to generate a transaction, and
// cancels after a deadline so it cannot hang.

using IotaSdk;

class Program
{
    const int DeadlineMillis = 60_000;

    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();
        var subscription = await client.TransactionsSubscription();

        var activity = Task.Run(async () =>
        {
            // Give the subscription a moment to connect before generating
            // activity, otherwise the transaction lands before anyone is
            // listening.
            await Task.Delay(2_000);
            var address = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");
            await FaucetClient.NewLocalnet().RequestAndWait(address);
        });
        // Cancelling unblocks a pending Next, which is what keeps the example
        // from waiting forever on a network that produces nothing.
        var watchdog = Task.Delay(DeadlineMillis).ContinueWith(_ => subscription.Cancel());

        Console.WriteLine("Waiting for a transaction...");
        while (true)
        {
            var update = await subscription.Next();
            if (update == null)
            {
                Console.WriteLine($"No transaction observed within {DeadlineMillis}ms");
                Environment.Exit(1);
            }

            if (update is TransactionUpdate.Transaction transaction)
            {
                var data = transaction.TransactionValue.Transaction;
                Console.WriteLine($"Digest: {data.Digest().ToBase58()}");
                Console.WriteLine($"Sender: {data.Sender().ToHex()}");
                break;
            }
            else if (update is TransactionUpdate.Interrupted interrupted)
            {
                // Delivery recovers on its own; items in the gap may be missed.
                Console.WriteLine($"Interrupted: {interrupted.Message}");
            }
        }

        subscription.Cancel();
    }
}
