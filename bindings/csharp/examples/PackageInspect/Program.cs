// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using IotaSdk;

class Program
{
    static PaginationFilter ForwardPage(string? cursor = null) =>
        new(Direction.Forward, cursor: cursor);

    static string FormatFunctionSignature(string signature, string packagePrefix) =>
        signature.Replace($"{packagePrefix}::", string.Empty);

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
        bool hasKeyAbility,
        bool isGeneric
    )
    {
        if (!hasKeyAbility)
        {
            return;
        }

        if (isGeneric)
        {
            Console.WriteLine("    sample objects: skipped for generic type");
            return;
        }

        var objects = await client.Objects(
            new ObjectFilter(typeTag: typeTag),
            new PaginationFilter(Direction.Forward, limit: 3)
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

    static string FormatPolicyName(byte policy) =>
        policy switch
        {
            0 => "Compatible",
            128 => "Additive",
            192 => "Dependency-only",
            _ => $"Unknown ({policy})"
        };

    static bool TryExtractPolicy(string contents, out byte policy)
    {
        try
        {
            using var json = JsonDocument.Parse(contents);
            if (!json.RootElement.TryGetProperty("policy", out var rawPolicy))
            {
                policy = 0;
                return false;
            }

            if (rawPolicy.ValueKind == JsonValueKind.Number)
            {
                return rawPolicy.TryGetByte(out policy);
            }

            if (rawPolicy.ValueKind == JsonValueKind.String)
            {
                return byte.TryParse(rawPolicy.GetString(), out policy);
            }
        }
        catch (JsonException)
        {
        }

        policy = 0;
        return false;
    }

    static async Task<ObjectId?> ResolveUpgradeCapId(GraphQlClient client, ObjectId packageId)
    {
        var page = await client.TransactionsEffects(
            new TransactionsFilter(changedObject: packageId),
            new PaginationFilter(Direction.Forward, limit: 1)
        );

        foreach (var effects in page.data)
        {
            var effectsV1 = effects.AsV1();
            foreach (var changedObj in effectsV1.changedObjects)
            {
                if (changedObj.outputState is not ObjectOut.ObjectWrite)
                {
                    continue;
                }

                var obj = await client.Object(changedObj.objectId, effectsV1.lamportVersion);
                if (
                    obj?.AsStructOpt()?.structType?.Equals(StructTag.NewUpgradeCap()) == true
                )
                {
                    return changedObj.objectId;
                }
            }
        }

        return null;
    }

    static async Task<string> CurrentPackagePolicy(GraphQlClient client, ObjectId packageId)
    {
        var upgradeCapId = await ResolveUpgradeCapId(client, packageId);
        if (upgradeCapId == null)
        {
            return "Unavailable";
        }

        var contents = await client.MoveObjectContents(upgradeCapId, null);
        if (contents == null)
        {
            return "Unavailable";
        }

        return TryExtractPolicy(contents, out var policy)
            ? FormatPolicyName(policy)
            : "Unavailable";
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
        Console.WriteLine(
            $"Current package policy: {await CurrentPackagePolicy(client, package.Id())}"
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
                    Console.WriteLine(
                        $"    - {FormatFunctionSignature(function.ToString(), packagePrefix)}"
                    );
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

                    var hasKeyAbility =
                        structType.abilities != null
                        && structType.abilities.Contains(MoveAbility.Key);
                    var isGeneric =
                        structType.typeParameters != null
                        && structType.typeParameters.Length > 0;
                    await PrintObjectSamples(client, typeTag, hasKeyAbility, isGeneric);
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
