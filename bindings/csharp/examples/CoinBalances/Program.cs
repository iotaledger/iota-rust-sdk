// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        try
        {
            var address = Address.FromHex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f");

            var coins = await client.Coins(address, null, null);

            foreach (var coin in coins.data)
            {
                Console.WriteLine($"Coin = {coin.Id().ToHex()}, Coin Type = {coin.CoinType().AsStructTag()}, Balance = {coin.Balance()}");
            }

            var balance = await client.Balance(address, null);
            Console.WriteLine($"Total Balance = {balance}");
        }
        catch (SdkFfiException ex)
        {
            Console.Error.WriteLine($"Failed to get coins/balance: {ex.Message}");
            Environment.Exit(1);
        }
    }
}
