// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        try
        {
            var address = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

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
