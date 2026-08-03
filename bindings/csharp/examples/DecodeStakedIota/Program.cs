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

        var owner = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");
        var filter = new ObjectFilter(TypeTag: "0x3::staking_pool::StakedIota", Owner: owner);

        var page = await client.Objects(filter);

        if (page.Data.Length == 0)
        {
            Console.WriteLine($"No StakedIota objects owned by {owner.ToHex()} right now.");
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
