// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example inspects a published Move package on testnet and prints its
// upgrade policy, version history, dependencies, functions, types, and sample
// objects.

using System.Text;
using System.Text.Json;
using IotaSdk;

class Program
{
    static readonly string FrameworkPackageId = CreateFrameworkPackageId();

    static async Task Main()
    {
        var packageId = "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d";

        var packageAddress = Address.FromHex(packageId);
        var client = GraphQlClient.NewTestnet();

        // Fetch package metadata and version history.
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
        Console.WriteLine(
            $"Latest version: {latestPackage.Version().AsU64()} ({latestPackage.Id().ToHex()})"
        );
        // Resolve the current upgrade policy.
        Console.WriteLine(
            $"Current package policy: {await CurrentPackagePolicy(client, package.Id())}"
        );
        Console.WriteLine();

        // Print the package version history.
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
            Console.WriteLine($"- v{version.Version().AsU64()} -> {version.Id().ToHex()}{suffix}");
        }
        Console.WriteLine();

        // Print package dependencies and their linked versions.
        Console.WriteLine("Dependencies:");
        var dependencies = package
            .LinkageTable()
            .Select(entry => entry.Value)
            .OrderBy(upgrade => upgrade.UpgradedId.ToHex())
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
                    $"- {dependency.UpgradedId.ToHex()} @ v{dependency.UpgradedVersion.AsU64()}"
                );
            }
        }
        Console.WriteLine();

        // Inspect normalized modules, functions, types, and sample key objects.
        Console.WriteLine("Package contents:");
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

            if (module.Functions == null || module.Functions.Nodes.Length == 0)
            {
                Console.WriteLine("  functions: none");
            }
            else
            {
                Console.WriteLine("  functions:");
                foreach (var function in module.Functions.Nodes)
                {
                    Console.WriteLine(
                        $"    - {FormatFunctionSignature(function.ToString(), packagePrefix)}"
                    );
                }
                if (module.Functions.PageInfo.HasNextPage)
                {
                    Console.WriteLine("    - ...");
                }
            }

            if (module.Structs == null || module.Structs.Nodes.Length == 0)
            {
                Console.WriteLine("  types: none");
            }
            else
            {
                Console.WriteLine("  types:");
                foreach (var structType in module.Structs.Nodes)
                {
                    var typeTag = $"{packagePrefix}::{moduleName}::{structType.Name}";
                    Console.WriteLine($"    - {typeTag}");

                    var hasKeyAbility =
                        structType.Abilities != null
                        && structType.Abilities.Contains(MoveAbility.Key);
                    var isGeneric =
                        structType.TypeParameters != null
                        && structType.TypeParameters.Length > 0;
                    await PrintObjectSamples(client, typeTag, hasKeyAbility, isGeneric);
                }
                if (module.Structs.PageInfo.HasNextPage)
                {
                    Console.WriteLine("    - ...");
                }
            }

            Console.WriteLine();
        }
    }

    static PaginationFilter ForwardPage(string? cursor = null) =>
        new(Direction.Forward, Cursor: cursor);

    static string CreateFrameworkPackageId()
    {
        using var framework = Address.Framework();
        return framework.ToHex();
    }

    static string ShortenPackageIds(string signature)
    {
        var shortened = new StringBuilder(signature.Length);
        var index = 0;

        while (index < signature.Length)
        {
            if (
                index + 2 <= signature.Length
                && signature[index] == '0'
                && signature[index + 1] == 'x'
            )
            {
                var end = index + 2;
                while (end < signature.Length && Uri.IsHexDigit(signature[end]))
                {
                    end++;
                }

                if (end > index + 2)
                {
                    var candidate = signature[index..end];
                    try
                    {
                        using var address = Address.FromHex(candidate);
                        shortened.Append(address.ToShortHex());
                    }
                    catch (SdkFfiException)
                    {
                        shortened.Append(candidate);
                    }

                    index = end;
                    continue;
                }
            }

            shortened.Append(signature[index]);
            index++;
        }

        return shortened.ToString();
    }

    static string FormatFunctionSignature(string signature, string packagePrefix) =>
        ShortenPackageIds(signature.Replace($"{packagePrefix}::", string.Empty));

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
            versions.AddRange(page.Data);

            if (page.PageInfo.HasNextPage)
            {
                cursor = page.PageInfo.EndCursor;
            }
            else
            {
                break;
            }
        }

        versions.Sort((left, right) => left.Version().AsU64().CompareTo(right.Version().AsU64()));
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
            new ObjectFilter(TypeTag: typeTag),
            new PaginationFilter(Direction.Forward, Limit: 3)
        );

        if (objects.Data.Length == 0)
        {
            Console.WriteLine("    sample objects: none found");
            return;
        }

        Console.WriteLine("    sample objects:");
        foreach (var obj in objects.Data)
        {
            Console.WriteLine($"      - {obj.Id().ToHex()} (version {obj.Version().AsU64()})");
        }
        if (objects.PageInfo.HasNextPage)
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
            new TransactionsFilter(ChangedObject: packageId),
            new PaginationFilter(Direction.Forward, Limit: 1)
        );

        foreach (var effects in page.Data)
        {
            var effectsV1 = effects.AsV1();
            foreach (var changedObj in effectsV1.ChangedObjects)
            {
                if (changedObj.OutputState is not ObjectOut.ObjectWrite)
                {
                    continue;
                }

                var obj = await client.Object(changedObj.ObjectId, effectsV1.LamportVersion);
                if (
                    obj?.AsStructOpt()?.StructType?.Equals(StructTag.NewUpgradeCap()) == true
                )
                {
                    return changedObj.ObjectId;
                }
            }
        }

        return null;
    }

    static bool SameObjectId(string? left, string? right) =>
        left != null
        && right != null
        && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    static bool TryGetProgrammableTransaction(Transaction tx, out JsonElement programmableTx)
    {
        using var json = JsonDocument.Parse(Iota.TransactionToJson(tx));
        programmableTx = default;

        if (
            !json.RootElement.TryGetProperty("1", out var txV1)
            || txV1.ValueKind != JsonValueKind.Object
            || !txV1.TryGetProperty("kind", out var kind)
            || kind.ValueKind != JsonValueKind.Object
            || !kind.TryGetProperty("kind", out var kindName)
            || kindName.GetString() != "programmable_transaction"
        )
        {
            return false;
        }

        programmableTx = kind.Clone();
        return true;
    }

    static bool IsPackageMakeImmutableCall(JsonElement command) =>
        command.ValueKind == JsonValueKind.Object
        && command.TryGetProperty("command", out var commandName)
        && commandName.GetString() == "move_call"
        && command.TryGetProperty("package", out var package)
        && SameObjectId(package.GetString(), FrameworkPackageId)
        && command.TryGetProperty("module", out var module)
        && module.GetString() == "package"
        && command.TryGetProperty("function", out var function)
        && function.GetString() == "make_immutable";

    static bool InputMatchesObjectId(JsonElement input, string objectId)
    {
        if (
            input.ValueKind != JsonValueKind.Object
            || !input.TryGetProperty("type", out var type)
            || !input.TryGetProperty("object_id", out var inputObjectId)
        )
        {
            return false;
        }

        return type.GetString() switch
        {
            "immutable_or_owned" or "receiving" or "shared" => SameObjectId(
                inputObjectId.GetString(),
                objectId
            ),
            _ => false
        };
    }

    static bool PublishesPackageAsImmutable(Transaction tx)
    {
        if (
            !TryGetProgrammableTransaction(tx, out var programmableTx)
            || !programmableTx.TryGetProperty("commands", out var commandsElement)
            || commandsElement.ValueKind != JsonValueKind.Array
        )
        {
            return false;
        }

        var commands = commandsElement.EnumerateArray().ToArray();
        var publishIndexes = commands
            .Select((command, index) => new { command, index })
            .Where(entry =>
                entry.command.ValueKind == JsonValueKind.Object
                && entry.command.TryGetProperty("command", out var commandName)
                && commandName.GetString() == "publish"
            )
            .Select(entry => entry.index)
            .ToArray();
        if (publishIndexes.Length != 1)
        {
            return false;
        }

        var publishIndex = publishIndexes[0];
        foreach (var command in commands.Skip(publishIndex + 1))
        {
            if (
                !IsPackageMakeImmutableCall(command)
                || !command.TryGetProperty("arguments", out var argumentsElement)
                || argumentsElement.ValueKind != JsonValueKind.Array
            )
            {
                continue;
            }

            var arguments = argumentsElement.EnumerateArray().ToArray();
            if (
                arguments.Length == 1
                && arguments[0].ValueKind == JsonValueKind.Object
                && arguments[0].TryGetProperty("result", out var result)
                && result.TryGetInt32(out var resultIndex)
                && resultIndex == publishIndex
            )
            {
                return true;
            }
        }

        return false;
    }

    static bool UsesUpgradeCapForMakeImmutable(Transaction tx, ObjectId upgradeCapId)
    {
        if (
            !TryGetProgrammableTransaction(tx, out var programmableTx)
            || !programmableTx.TryGetProperty("inputs", out var inputsElement)
            || inputsElement.ValueKind != JsonValueKind.Array
            || !programmableTx.TryGetProperty("commands", out var commandsElement)
            || commandsElement.ValueKind != JsonValueKind.Array
        )
        {
            return false;
        }

        var upgradeCapInputs = inputsElement
            .EnumerateArray()
            .Select((input, index) => new { input, index })
            .Where(entry => InputMatchesObjectId(entry.input, upgradeCapId.ToHex()))
            .Select(entry => entry.index)
            .ToHashSet();
        if (upgradeCapInputs.Count == 0)
        {
            return false;
        }

        foreach (var command in commandsElement.EnumerateArray())
        {
            if (
                !IsPackageMakeImmutableCall(command)
                || !command.TryGetProperty("arguments", out var argumentsElement)
                || argumentsElement.ValueKind != JsonValueKind.Array
            )
            {
                continue;
            }

            var arguments = argumentsElement.EnumerateArray().ToArray();
            if (
                arguments.Length == 1
                && arguments[0].ValueKind == JsonValueKind.Object
                && arguments[0].TryGetProperty("input", out var input)
                && input.TryGetInt32(out var inputIndex)
                && upgradeCapInputs.Contains(inputIndex)
            )
            {
                return true;
            }
        }

        return false;
    }

    static async Task<bool> WasPackagePublishedAsImmutable(
        GraphQlClient client,
        ObjectId packageId
    )
    {
        string? cursor = null;

        while (true)
        {
            var page = await client.TransactionsDataEffects(
                new TransactionsFilter(ChangedObject: packageId),
                ForwardPage(cursor)
            );

            foreach (var txData in page.Data)
            {
                if (PublishesPackageAsImmutable(txData.Tx.Transaction))
                {
                    return true;
                }
            }

            if (!page.PageInfo.HasNextPage)
            {
                return false;
            }

            cursor = page.PageInfo.EndCursor;
        }
    }

    static async Task<bool> WasUpgradeCapUsedForMakeImmutable(
        GraphQlClient client,
        ObjectId upgradeCapId
    )
    {
        string? cursor = null;

        while (true)
        {
            var page = await client.TransactionsDataEffects(
                new TransactionsFilter(InputObject: upgradeCapId),
                ForwardPage(cursor)
            );

            foreach (var txData in page.Data)
            {
                if (UsesUpgradeCapForMakeImmutable(txData.Tx.Transaction, upgradeCapId))
                {
                    return true;
                }
            }

            if (!page.PageInfo.HasNextPage)
            {
                return false;
            }

            cursor = page.PageInfo.EndCursor;
        }
    }

    static async Task<string> CurrentPackagePolicy(GraphQlClient client, ObjectId packageId)
    {
        var upgradeCapId = await ResolveUpgradeCapId(client, packageId);
        if (upgradeCapId == null)
        {
            if (await WasPackagePublishedAsImmutable(client, packageId))
            {
                return "Immutable";
            }

            return "Unavailable";
        }

        var contents = await client.MoveObjectContents(upgradeCapId, null);
        if (contents == null)
        {
            if (await WasUpgradeCapUsedForMakeImmutable(client, upgradeCapId))
            {
                return "Immutable";
            }

            return "Unavailable";
        }

        return TryExtractPolicy(contents, out var policy)
            ? FormatPolicyName(policy)
            : "Unavailable";
    }

}
