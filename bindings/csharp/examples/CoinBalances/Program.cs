// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        try
        {
            var address = Address.FromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522");
            await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(address, client);

            var coins = await client.Coins(address, null, null);

            foreach (var coin in coins.data)
            {
                Console.WriteLine($"Coin = {coin.Id().ToHex()}, Coin Type = {coin.CoinType().AsStructTag()}, Balance = {coin.Balance()}");
            }

            var balance = await client.Balance(address, null) ?? 0;
            Console.WriteLine($"Total Balance = {balance}");
        }
        catch (SdkFfiException ex)
        {
            Console.Error.WriteLine($"Failed to get coins/balance: {ex.Message}");
            Environment.Exit(1);
        }
    }
}
