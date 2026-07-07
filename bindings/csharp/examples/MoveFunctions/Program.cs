// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var packageAddress = Address.FromHex("0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d");

        var package = await client.Package(packageAddress);
        if (package == null)
        {
            throw new Exception("missing package");
        }

        foreach (var moduleId in package.Modules())
        {
            var module = await client.NormalizedMoveModule(packageAddress, moduleId.Key.AsStr());
            if (module == null)
            {
                Console.WriteLine($"module `{moduleId.Key.AsStr()}` not found");
                return;
            }
            if (module.Functions != null)
            {
                Console.WriteLine($"Module: {moduleId.Key.AsStr()}");
                foreach (var fun in module.Functions.Nodes)
                {
                    Console.WriteLine($"- {fun.ToString()}");
                }
                Console.WriteLine();
            }
        }
    }
}
