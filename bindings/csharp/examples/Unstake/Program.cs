// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        // Filtering by type alone scans every object on the network, which the
        // GraphQL server rejects with a timeout, so filter by owner as well.
        var owner = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        var stakedIotas = await client.Objects(new ObjectFilter(TypeTag: StructTag.NewStakedIota().ToString(), Owner: owner));
        if (stakedIotas.Data.Length == 0)
        {
            throw new Exception("no staked iotas found");
        }
        var stakedIota = stakedIotas.Data[0];

        var builder = new TransactionBuilder(stakedIota.Owner().AsAddress()).WithClient(client);

        builder.Unstake(PtbArgument.ObjectId(stakedIota.Id()));

        var res = await builder.DryRun(false);

        if (res.Error != null)
        {
            throw new Exception($"Failed to unstake: {res.Error}");
        }

        Console.WriteLine("Unstake dry run was successful!");
    }
}
