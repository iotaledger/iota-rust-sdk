// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        // Query events emitted by the validator-set module in the IOTA system
        // framework (0x3). These fire on every epoch change so they are reliably
        // present on every network including localnet.
        EventPage events;
        try
        {
            events = await client.Events(
                new EventFilter(eventType: "0x3::validator::StakingRequestEvent"),
                new PaginationFilter(Direction.Forward, null, 10)
            );
        }
        catch (PanicException)
        {
            // System-emitted events on localnet can lack a `sender` or
            // `sendingModule` field. The current FFI conversion of `Event`
            // requires both fields and panics on `None`, so we surface a
            // friendly message instead of aborting.
            Console.WriteLine("No printable events: system-emitted events on localnet have no sender.");
            return;
        }

        foreach (var evt in events.data)
        {
            Console.WriteLine($"Type: {evt.@type}");
            Console.WriteLine($"Sender: {evt.sender.ToHex()}");
            Console.WriteLine($"Module: {evt.module}");
            Console.WriteLine($"JSON: {evt.json}");
        }
    }
}
