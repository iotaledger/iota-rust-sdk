// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var events = await client.Events(
            new EventFilter(EventType: "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent"),
            new PaginationFilter(Direction.Forward, null, 10)
        );

        foreach (var evt in events.Data)
        {
            // Sender and module are optional: some events (such as system- or
            // genesis-emitted ones) carry neither.
            Console.WriteLine($"Type: {evt.Type}");
            Console.WriteLine($"Sender: {evt.Sender?.ToHex() ?? "none"}");
            Console.WriteLine($"Module: {evt.Module ?? "none"}");
            Console.WriteLine($"JSON: {evt.Json}");
        }
    }
}
