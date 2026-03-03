// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var events = await client.Events(
            new EventFilter(eventType: "0x7aec8176867a0c8d2803d758ebf98226d301ef0f00393879ea718f6bd1554f16::registry::NameRecordAddedEvent"),
            new PaginationFilter(Direction.Forward, null, 10)
        );

        foreach (var evt in events.data)
        {
            Console.WriteLine($"Type: {evt.@type}");
            Console.WriteLine($"Sender: {evt.sender.ToHex()}");
            Console.WriteLine($"Module: {evt.module}");
            Console.WriteLine($"JSON: {evt.json}");
        }
    }
}
