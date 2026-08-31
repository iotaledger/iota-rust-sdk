// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var myAddress = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        var validators = await client.ActiveValidators();
        if (validators.Data.Length == 0)
        {
            throw new Exception("no validators found");
        }
        var validator = validators.Data[0];

        Console.WriteLine($"Staking to validator {validator.Name ?? "with no name"}");

        var builder = client.TransactionBuilder(myAddress);

        builder.Stake(PtbArgument.U64(1000000000), validator.Address);

        var res = await builder.DryRun(false);

        if (res.Error != null)
        {
            throw new Exception($"Failed to stake: {res.Error}");
        }

        Console.WriteLine("Stake dry run was successful!");
    }
}
