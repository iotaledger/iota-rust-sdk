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
        var filter = new ObjectFilter(typeTag: "0x3::staking_pool::StakedIota");

        var page = await client.Objects(filter);

        if (page.data.Length == 0)
        {
            Console.WriteLine("No StakedIota objects on testnet right now.");
            return;
        }

        Console.WriteLine($"Decoded {page.data.Length} StakedIota object(s):\n");
        ulong totalPrincipal = 0;
        foreach (var obj in page.data)
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
