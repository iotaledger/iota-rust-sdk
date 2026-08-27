// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// 2-of-3 Ed25519 multisig example.
//
// Derives 3 keypairs from a mnemonic at indices 0, 1, 2, creates a multisig
// committee with threshold 2, funds the multisig address via faucet, builds
// a send_iota transaction, signs with only 2 of the 3 keys, aggregates,
// and executes.
//
// Requires a running localnet (`iota start --force-regenesis`).

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

const MNEMONIC = "round attack kitchen wink winter music trip tiny nephew hire orange what"

func main() {
	recipientAddress, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	// 1. Derive 3 Ed25519 keypairs from mnemonic at indices 0, 1, 2
	key0, err := iota_sdk.Ed25519PrivateKeyFromMnemonic(MNEMONIC, 0, "")
	if err != nil {
		log.Fatalf("Failed to derive key0: %v", err)
	}
	key1, err := iota_sdk.Ed25519PrivateKeyFromMnemonic(MNEMONIC, 1, "")
	if err != nil {
		log.Fatalf("Failed to derive key1: %v", err)
	}
	key2, err := iota_sdk.Ed25519PrivateKeyFromMnemonic(MNEMONIC, 2, "")
	if err != nil {
		log.Fatalf("Failed to derive key2: %v", err)
	}

	// 2. Get MultisigMemberPublicKey via SimpleKeypair
	kp0 := iota_sdk.SimpleKeypairFromEd25519(key0)
	kp1 := iota_sdk.SimpleKeypairFromEd25519(key1)
	kp2 := iota_sdk.SimpleKeypairFromEd25519(key2)

	// 3. Build multisig committee: threshold=2, each member weight=1
	committee, err := iota_sdk.NewMultisigCommittee(
		[]*iota_sdk.MultisigMember{
			iota_sdk.NewMultisigMember(kp0.PublicKey(), 1),
			iota_sdk.NewMultisigMember(kp1.PublicKey(), 1),
			iota_sdk.NewMultisigMember(kp2.PublicKey(), 1),
		},
		2,
	)
	if err != nil {
		log.Fatalf("Failed to create committee: %v", err)
	}

	// 4. Derive multisig address
	multisigAddress := committee.DeriveAddress()
	log.Printf("Multisig address: %s", multisigAddress.ToHex())

	client := iota_sdk.GraphQlClientNewLocalnet()

	// 5. Fund the multisig address
	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWaitForFinalized(multisigAddress, client)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	// 6. Build a send_iota transaction
	builder := client.TransactionBuilder(multisigAddress)
	builder.SendIota(recipientAddress, iota_sdk.PtbArgumentU64(1000))
	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	dryRunResult, err := client.DryRunTx(txn, false)
	if err != nil {
		log.Fatalf("Failed to dry run: %v", err)
	}
	if dryRunResult.Error != nil {
		log.Fatalf("Dry run failed: %v", *dryRunResult.Error)
	}

	// 7. Sign with key0 and key1 (2-of-3 threshold)
	sig0, err := kp0.SignTransaction(txn)
	if err != nil {
		log.Fatalf("Failed to sign with key0: %v", err)
	}
	sig1, err := kp1.SignTransaction(txn)
	if err != nil {
		log.Fatalf("Failed to sign with key1: %v", err)
	}

	// 8. Aggregate signatures
	aggregator := iota_sdk.MultisigAggregatorNewWithTransaction(committee, txn)
	if err = aggregator.AddSignature(sig0); err != nil {
		log.Fatalf("Failed to add sig0: %v", err)
	}
	if err = aggregator.AddSignature(sig1); err != nil {
		log.Fatalf("Failed to add sig1: %v", err)
	}
	aggSig, err := aggregator.Finish()
	if err != nil {
		log.Fatalf("Failed to finish aggregation: %v", err)
	}

	// 9. Execute
	userSignature := iota_sdk.UserSignatureNewMultisig(aggSig)
	effects, err := client.ExecuteTx([]*iota_sdk.UserSignature{userSignature}, txn, nil)
	if err != nil {
		log.Fatalf("Failed to execute: %v", err)
	}
	log.Printf("Digest: %s", iota_sdk.HexEncode((*effects).Digest().ToBytes()))
	log.Printf("Transaction status: %v", (*effects).AsV1().Status)
	log.Printf("Effects: %+v", (*effects).AsV1())
}
