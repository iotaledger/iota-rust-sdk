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

        var myAddress = Address.FromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c");

        var validators = await client.ActiveValidators();
        if (validators.data.Length == 0)
        {
            throw new Exception("no validators found");
        }
        var validator = validators.data[0];

        Console.WriteLine($"Staking to validator {validator.name ?? "with no name"}");

        var builder = new TransactionBuilder(myAddress).WithClient(client);

        builder.Stake(PtbArgument.U64(1000000000), validator.address);

        var res = await builder.DryRun(false);

        if (res.error != null)
        {
            throw new Exception($"Failed to stake: {res.error}");
        }

        Console.WriteLine("Stake dry run was successful!");
    }
}
