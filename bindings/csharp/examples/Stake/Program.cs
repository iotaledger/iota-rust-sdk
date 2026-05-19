// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var myAddress = Address.FromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522");

        await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(myAddress, client);

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
