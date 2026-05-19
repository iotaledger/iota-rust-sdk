// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var stakedIotas = await client.Objects(new ObjectFilter(typeTag: StructTag.NewStakedIota().ToString()));
        if (stakedIotas.data.Length == 0)
        {
            throw new Exception("no staked iotas found");
        }
        var stakedIota = stakedIotas.data[0];
        var staker = stakedIota.Owner().AsAddress();

        var builder = new TransactionBuilder(staker).WithClient(client);
        builder.Unstake(PtbArgument.ObjectId(stakedIota.ObjectId()));

        var res = await builder.DryRun(false);

        if (res.error != null)
        {
            throw new Exception($"Failed to unstake: {res.error}");
        }

        Console.WriteLine("Unstake dry run was successful!");
    }
}
