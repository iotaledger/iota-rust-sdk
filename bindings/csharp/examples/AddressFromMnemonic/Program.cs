// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using System;
using IotaSdk;

class Program
{
    static void Main(string[] args)
    {
        var mnemonic = "round attack kitchen wink winter music trip tiny nephew hire orange what";

        var privateKey1 = Ed25519PrivateKey.FromMnemonic(mnemonic, 0);
        var privateKeyBech321 = privateKey1.ToBech32();
        var publicKey1 = privateKey1.PublicKey();
        var flaggedPublicKey1 = publicKey1.ToFlaggedBytes();
        var address1 = publicKey1.DeriveAddress();

        Console.WriteLine($"Ed25519\n---");
        Console.WriteLine($"Private Key: {privateKeyBech321}");
        Console.WriteLine($"Public Key: {Iota.Base64Encode(publicKey1.ToBytes())}");
        Console.WriteLine($"Public Key With Flag: {Iota.Base64Encode(flaggedPublicKey1)}");
        Console.WriteLine($"Address: {address1.ToHex()}");

        var privateKey2 = Secp256k1PrivateKey.FromMnemonic(mnemonic, 1);
        var privateKeyBech322 = privateKey2.ToBech32();
        var publicKey2 = privateKey2.PublicKey();
        var flaggedPublicKey2 = publicKey2.ToFlaggedBytes();
        var address2 = publicKey2.DeriveAddress();

        Console.WriteLine($"\nSecp256k1\n---");
        Console.WriteLine($"Private Key: {privateKeyBech322}");
        Console.WriteLine($"Public Key: {Iota.Base64Encode(publicKey2.ToBytes())}");
        Console.WriteLine($"Public Key With Flag: {Iota.Base64Encode(flaggedPublicKey2)}");
        Console.WriteLine($"Address: {address2.ToHex()}");

        var privateKey3 = Secp256r1PrivateKey.FromMnemonicWithPath(mnemonic, "m/74'/4218'/0'/0/2");
        var privateKeyBech323 = privateKey3.ToBech32();
        var publicKey3 = privateKey3.PublicKey();
        var flaggedPublicKey3 = publicKey3.ToFlaggedBytes();
        var address3 = publicKey3.DeriveAddress();

        Console.WriteLine($"\nSecp256r1\n---");
        Console.WriteLine($"Private Key: {privateKeyBech323}");
        Console.WriteLine($"Public Key: {Iota.Base64Encode(publicKey3.ToBytes())}");
        Console.WriteLine($"Public Key With Flag: {Iota.Base64Encode(flaggedPublicKey3)}");
        Console.WriteLine($"Address: {address3.ToHex()}");
    }
}
