// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static PaginationFilter ForwardPage(string? cursor = null) =>
        new(Direction.Forward, cursor: cursor);

    static async Task<List<MovePackage>> FetchPackageVersions(
        GraphQlClient client,
        Address packageAddress
    )
    {
        var versions = new List<MovePackage>();
        string? cursor = null;

        while (true)
        {
            var page = await client.PackageVersions(
                packageAddress,
                paginationFilter: ForwardPage(cursor)
            );
            versions.AddRange(page.data);

            if (page.pageInfo.hasNextPage)
            {
                cursor = page.pageInfo.endCursor;
            }
            else
            {
                break;
            }
        }

        versions.Sort((left, right) => left.Version().CompareTo(right.Version()));
        return versions;
    }

    static async Task PrintObjectSamples(
        GraphQlClient client,
        string typeTag,
        bool isGeneric
    )
    {
        if (isGeneric)
        {
            Console.WriteLine("    sample objects: skipped for generic type");
            return;
        }

        var objects = await client.Objects(
            new ObjectFilter(typeTag: typeTag),
            ForwardPage()
        );

        if (objects.data.Length == 0)
        {
            Console.WriteLine("    sample objects: none found");
            return;
        }

        Console.WriteLine("    sample objects:");
        foreach (var obj in objects.data)
        {
            Console.WriteLine($"      - {obj.ObjectId().ToHex()} (version {obj.Version()})");
        }
        if (objects.pageInfo.hasNextPage)
        {
            Console.WriteLine("      - ...");
        }
    }

    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            throw new ArgumentException(
                "Usage: dotnet run --project PackageInspect -- <PACKAGE_ID>"
            );
        }
        var packageId = args[0];

        var packageAddress = Address.FromHex(packageId);
        var client = GraphQlClient.NewTestnet();

        var package = await client.Package(packageAddress);
        if (package == null)
        {
            throw new Exception("missing package");
        }

        var latestPackage = await client.PackageLatest(packageAddress);
        if (latestPackage == null)
        {
            throw new Exception("missing latest package");
        }

        var versions = await FetchPackageVersions(client, packageAddress);
        var packagePrefix = package.Id().ToHex();

        Console.WriteLine($"Requested package id: {packageId}");
        Console.WriteLine($"Resolved package id: {packagePrefix}");
        Console.WriteLine($"Resolved version: {package.Version()}");
        Console.WriteLine(
            $"Latest version: {latestPackage.Version()} ({latestPackage.Id().ToHex()})"
        );
        Console.WriteLine();

        Console.WriteLine("Versions:");
        foreach (var version in versions)
        {
            var labels = new List<string>();
            if (version.Id().Equals(package.Id()))
            {
                labels.Add("requested");
            }
            if (version.Id().Equals(latestPackage.Id()))
            {
                labels.Add("latest");
            }

            var suffix = labels.Count == 0 ? string.Empty : $" [{string.Join(", ", labels)}]";
            Console.WriteLine($"- v{version.Version()} -> {version.Id().ToHex()}{suffix}");
        }
        Console.WriteLine();

        Console.WriteLine("Dependencies:");
        var dependencies = package
            .LinkageTable()
            .OrderBy(entry => entry.Key.ToHex())
            .ToArray();
        if (dependencies.Length == 0)
        {
            Console.WriteLine("- none");
        }
        else
        {
            foreach (var dependency in dependencies)
            {
                Console.WriteLine(
                    $"- {dependency.Key.ToHex()} -> {dependency.Value.upgradedId.ToHex()} @ v{dependency.Value.upgradedVersion}"
                );
            }
        }
        Console.WriteLine();

        Console.WriteLine("Modules, functions, and types:");
        var moduleNames = package
            .Modules()
            .Keys
            .Select(moduleId => moduleId.AsStr())
            .OrderBy(moduleName => moduleName);

        foreach (var moduleName in moduleNames)
        {
            Console.WriteLine($"Module: {moduleName}");

            var module = await client.NormalizedMoveModule(
                packageAddress,
                moduleName,
                paginationFilterEnums: ForwardPage(),
                paginationFilterFriends: ForwardPage(),
                paginationFilterFunctions: ForwardPage(),
                paginationFilterStructs: ForwardPage()
            );
            if (module == null)
            {
                Console.WriteLine("  metadata: missing");
                Console.WriteLine();
                continue;
            }

            if (module.functions == null || module.functions.nodes.Length == 0)
            {
                Console.WriteLine("  functions: none");
            }
            else
            {
                Console.WriteLine("  functions:");
                foreach (var function in module.functions.nodes)
                {
                    Console.WriteLine($"    - {function}");
                }
                if (module.functions.pageInfo.hasNextPage)
                {
                    Console.WriteLine("    - ...");
                }
            }

            if (module.structs == null || module.structs.nodes.Length == 0)
            {
                Console.WriteLine("  types: none");
            }
            else
            {
                Console.WriteLine("  types:");
                foreach (var structType in module.structs.nodes)
                {
                    var typeTag = $"{packagePrefix}::{moduleName}::{structType.name}";
                    Console.WriteLine($"    - {typeTag}");

                    var isGeneric =
                        structType.typeParameters != null
                        && structType.typeParameters.Length > 0;
                    await PrintObjectSamples(client, typeTag, isGeneric);
                }
                if (module.structs.pageInfo.hasNextPage)
                {
                    Console.WriteLine("    - ...");
                }
            }

            Console.WriteLine();
        }
    }
}
