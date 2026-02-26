// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        var events = await client.Events(
            new EventFilter(eventType: "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba::registry::NameRecordAddedEvent"),
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
