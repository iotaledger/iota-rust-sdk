// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        // Inspect the IOTA framework package (0x2). It is present on every network
        // including localnet.
        var packageAddress = Address.Framework();

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
            if (module.functions != null)
            {
                Console.WriteLine($"Module: {moduleId.Key.AsStr()}");
                foreach (var fun in module.functions.nodes)
                {
                    Console.WriteLine($"- {fun.ToString()}");
                }
                Console.WriteLine();
            }
        }
    }
}
