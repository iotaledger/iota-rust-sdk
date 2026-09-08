// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var privateKey = Ed25519PrivateKey.Random();
        var owner = privateKey.PublicKey().DeriveAddress();

        var faucet = FaucetClient.NewLocalnet();
        await faucet.RequestAndWaitForFinalized(owner, client);

        var validators = await client.ActiveValidators();
        if (validators.Data.Length == 0)
        {
            throw new Exception("no validators found");
        }
        var stakeBuilder = client.TransactionBuilder(owner);
        stakeBuilder.Stake(PtbArgument.U64(1000000000), validators.Data[0].Address);
        var stakeTx = await stakeBuilder.Finish();
        var signature = privateKey.SignTransaction(stakeTx);
        await client.ExecuteTransaction(new[] { signature }, stakeTx, WaitForTransaction.Finalized);

        var stakedIotas = await client.Objects(new ObjectFilter(TypeTag: StructTag.NewStakedIota().ToString(), Owner: owner));
        if (stakedIotas.Data.Length == 0)
        {
            throw new Exception("no staked iotas found");
        }
        var stakedIota = stakedIotas.Data[0];

        var builder = client.TransactionBuilder(stakedIota.Owner().AsAddress());

        builder.Unstake(PtbArgument.ObjectId(stakedIota.Id()));

        var res = await builder.DryRun(false);

        if (res.Error != null)
        {
            throw new Exception($"Failed to unstake: {res.Error}");
        }

        Console.WriteLine("Unstake dry run was successful!");
    }
}
