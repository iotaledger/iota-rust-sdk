// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    // A pre-encoded programmable transaction calling `0x1::u64::max(1, 2)` with
    // empty gas-payment objects. Because the bytes do not reference any on-chain
    // object refs, they stay valid across networks — the dry-run endpoint fills
    // in gas coins on demand.
    const string TxBytesBase64 = "AAACAAgBAAAAAAAAAAAIAgAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA3U2NANtYXgAAgEAAAEBACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUiACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUi6AMAAAAAAAAAAAAAAAAAAAA=";

    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var transaction = Transaction.FromBase64(TxBytesBase64);

        var res = await client.DryRunTx(transaction);
        if (res.error != null)
        {
            throw new Exception($"Dry run failed: {res.error}");
        }

        Console.WriteLine("Dry run was successful!");
        Console.WriteLine($"Dry run result: {res}");
    }
}
