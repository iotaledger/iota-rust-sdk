// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Decode StakedIota objects into typed C# values.
//
// The GraphQL client returns each object's contents as raw BCS bytes. A single
// StakedIota.TryFromObject(obj) call gives typed, named-field access to
// Id / PoolId / StakeActivationEpoch / Principal.

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        // Filtering objects by type alone scans every object on the network, which
        // the GraphQL server rejects with a timeout. Pick a recent staker and filter
        // by owner as well, so only that address' objects are looked at.
        var stakers = await client.Transactions(
            new TransactionsFilter(Function: "0x3::iota_system::request_add_stake"),
            new PaginationFilter(Direction.Backward, Limit: 1));

        if (stakers.Data.Length == 0)
        {
            Console.WriteLine("No staking transactions on testnet right now.");
            return;
        }

        var staker = stakers.Data[^1].Transaction.Sender();
        Console.WriteLine($"Latest staker: {staker.ToHex()}\n");

        var filter = new ObjectFilter(TypeTag: "0x3::staking_pool::StakedIota", Owner: staker);

        var page = await client.Objects(filter);

        if (page.Data.Length == 0)
        {
            Console.WriteLine($"No StakedIota objects owned by {staker.ToHex()} right now.");
            return;
        }

        Console.WriteLine($"Decoded {page.Data.Length} StakedIota object(s):\n");
        ulong totalPrincipal = 0;
        foreach (var obj in page.Data)
        {
            var staked = StakedIota.TryFromObject(obj);
            totalPrincipal += staked.Principal();
            Console.WriteLine($"- id:               {staked.Id().ToHex()}");
            Console.WriteLine($"  pool_id:          {staked.PoolId().ToHex()}");
            Console.WriteLine($"  stake_activation_epoch: {staked.StakeActivationEpoch()}");
            Console.WriteLine($"  principal (nanos): {staked.Principal()}\n");
        }

        Console.WriteLine($"Total principal across page: {totalPrincipal} nanos");
    }
}
