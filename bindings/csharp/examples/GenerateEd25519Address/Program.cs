// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static void Main(string[] args)
    {
        var privateKey = Ed25519PrivateKey.Random();
        var privateKeyBech32 = privateKey.ToBech32();
        var publicKey = privateKey.PublicKey();
        var flaggedPublicKey = publicKey.ToFlaggedBytes();
        var address = publicKey.DeriveAddress();

        Console.WriteLine($"Private Key: {privateKeyBech32}");
        Console.WriteLine($"Public Key: {Iota.Base64Encode(publicKey.ToBytes())}");
        Console.WriteLine($"Public Key With Flag: {Iota.Base64Encode(flaggedPublicKey)}");
        Console.WriteLine($"Address: {address.ToHex()}");
    }
}
