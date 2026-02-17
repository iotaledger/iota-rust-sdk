// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Milestone 1 translation of bindings/python/examples/address_from_mnemonic.py.
// This file is scaffold-only until generated C# bindings are wired in.

using System;
using IotaSdk;

const string Mnemonic = "round attack kitchen wink winter music trip tiny nephew hire orange what";

var ed25519PrivateKey = Ed25519PrivateKey.FromMnemonic(Mnemonic);
var ed25519PublicKey = ed25519PrivateKey.PublicKey();
var ed25519Address = ed25519PublicKey.DeriveAddress();

Console.WriteLine("Ed25519");
Console.WriteLine("---");
Console.WriteLine($"Private Key: {ed25519PrivateKey.ToBech32()}");
Console.WriteLine($"Public Key: {Convert.ToBase64String(ed25519PublicKey.ToBytes())}");
Console.WriteLine($"Public Key With Flag: {Convert.ToBase64String(ed25519PublicKey.ToFlaggedBytes())}");
Console.WriteLine($"Address: {ed25519Address.ToHex()}");

var secp256k1PrivateKey = Secp256k1PrivateKey.FromMnemonic(Mnemonic, 1);
var secp256k1PublicKey = secp256k1PrivateKey.PublicKey();
var secp256k1Address = secp256k1PublicKey.DeriveAddress();

Console.WriteLine("\nSecp256k1");
Console.WriteLine("---");
Console.WriteLine($"Private Key: {secp256k1PrivateKey.ToBech32()}");
Console.WriteLine($"Public Key: {Convert.ToBase64String(secp256k1PublicKey.ToBytes())}");
Console.WriteLine($"Public Key With Flag: {Convert.ToBase64String(secp256k1PublicKey.ToFlaggedBytes())}");
Console.WriteLine($"Address: {secp256k1Address.ToHex()}");

var secp256r1PrivateKey = Secp256r1PrivateKey.FromMnemonicWithPath(Mnemonic, "m/74'/4218'/0'/0/2");
var secp256r1PublicKey = secp256r1PrivateKey.PublicKey();
var secp256r1Address = secp256r1PublicKey.DeriveAddress();

Console.WriteLine("\nSecp256r1");
Console.WriteLine("---");
Console.WriteLine($"Private Key: {secp256r1PrivateKey.ToBech32()}");
Console.WriteLine($"Public Key: {Convert.ToBase64String(secp256r1PublicKey.ToBytes())}");
Console.WriteLine($"Public Key With Flag: {Convert.ToBase64String(secp256r1PublicKey.ToFlaggedBytes())}");
Console.WriteLine($"Address: {secp256r1Address.ToHex()}");
