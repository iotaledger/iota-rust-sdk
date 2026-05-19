// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        // The IOTA system state object owns the validator set and other dynamic
        // fields. It is available on every network including localnet.
        var parentObjectId = Address.SystemState();
        var page = await client.DynamicFields(parentObjectId);

        Console.WriteLine($"Page size: {page.data.Length}");
        if (page.data.Length > 0)
        {
            Console.WriteLine("First field name:");
            Console.WriteLine(page.data[0].name);

            // The field value can be large (e.g. the validator set on 0x5), so we
            // print only the first few lines as a preview.
            const int previewLines = 15;
            using var json = JsonDocument.Parse(page.data[0].valueAsJson);
            var valuePretty = JsonSerializer.Serialize(json.RootElement, new JsonSerializerOptions { WriteIndented = true });
            var lines = valuePretty.Split('\n');
            var preview = string.Join("\n", lines.Take(previewLines));
            Console.WriteLine($"First field value (first {previewLines} lines):");
            Console.WriteLine(preview);
            if (lines.Length > previewLines)
            {
                Console.WriteLine("... [truncated]");
            }
        }
    }
}
