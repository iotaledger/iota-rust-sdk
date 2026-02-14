// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func failOnErr(context string, err error) {
	if err == nil {
		return
	}
	if sdkErr, ok := err.(*iota_sdk.SdkFfiError); ok {
		log.Fatalf("%s: %v", context, sdkErr)
	}
	log.Fatalf("%s: %v", context, err)
}

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()
	faucetClient := iota_sdk.FaucetClientNewLocalnet()

	recipient, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	failOnErr("parse recipient address", err)
	amount := uint64(1_000)

	// Deterministic keys for the example. Do not use hardcoded mnemonics in production.
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	key1, err := iota_sdk.Ed25519PrivateKeyFromMnemonic(mnemonic, 0, "")
	failOnErr("create key1", err)
	key2, err := iota_sdk.Ed25519PrivateKeyFromMnemonic(mnemonic, 1, "")
	failOnErr("create key2", err)

	pk1 := key1.PublicKey()
	pk2 := key2.PublicKey()

	// Create MultisigMemberPublicKey objects via JSON conversion.
	// Format: {"scheme":"ed25519","public_key":"<base64-32-bytes>"}
	pk1b64 := base64.StdEncoding.EncodeToString(pk1.ToBytes())
	pk2b64 := base64.StdEncoding.EncodeToString(pk2.ToBytes())
	mpk1, err := iota_sdk.MultisigMemberPublicKeyFromJson(
		fmt.Sprintf(`{"scheme":"ed25519","public_key":"%s"}`, pk1b64),
	)
	failOnErr("create multisig member public key 1", err)
	mpk2, err := iota_sdk.MultisigMemberPublicKeyFromJson(
		fmt.Sprintf(`{"scheme":"ed25519","public_key":"%s"}`, pk2b64),
	)
	failOnErr("create multisig member public key 2", err)

	member1 := iota_sdk.NewMultisigMember(mpk1, 1)
	member2 := iota_sdk.NewMultisigMember(mpk2, 1)
	committee := iota_sdk.NewMultisigCommittee([]*iota_sdk.MultisigMember{member1, member2}, 2)

	multisigAddress := committee.DeriveAddress()
	fmt.Printf("Multisig address: %s\n", multisigAddress.ToHex())

	_, err = faucetClient.RequestAndWaitForFinalized(multisigAddress, client)
	failOnErr("faucet request", err)

	builder := iota_sdk.NewTransactionBuilder(multisigAddress).WithClient(client)
	builder.SendIota(recipient, iota_sdk.PtbArgumentU64(amount))

	tx, err := builder.Finish()
	failOnErr("build transaction", err)

	dryRun, err := client.DryRunTx(tx, false)
	failOnErr("dry run transaction", err)
	if dryRun.Error != nil {
		log.Fatalf("dry run failed: %v", *dryRun.Error)
	}

	sig1, err := key1.SignTransaction(tx)
	failOnErr("sign tx (key1)", err)
	sig2, err := key2.SignTransaction(tx)
	failOnErr("sign tx (key2)", err)

	aggregator := iota_sdk.MultisigAggregatorNewWithTransaction(committee, tx)
	aggregator, err = aggregator.WithSignature(sig1)
	failOnErr("add signature (key1)", err)
	aggregator, err = aggregator.WithSignature(sig2)
	failOnErr("add signature (key2)", err)

	aggSig, err := aggregator.Finish()
	failOnErr("finish multisig aggregation", err)

	msUserSig := iota_sdk.UserSignatureNewMultisig(aggSig)
	effects, err := client.ExecuteTx([]*iota_sdk.UserSignature{msUserSig}, tx, nil)
	failOnErr("execute transaction", err)

	fmt.Printf("Digest: %s\n", iota_sdk.HexEncode((*effects).Digest().ToBytes()))
	fmt.Printf("Status: %v\n", (*effects).AsV1().Status)
}
