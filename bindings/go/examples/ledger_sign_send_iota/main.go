// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Send IOTA from a Ledger device's address on a local network. Set
// LEDGER_SIMULATOR to use the Speculos emulator instead of a device.
package main

import (
	"log"
	"os"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	// Amount to send in nanos
	amount := uint64(1000)
	recipientAddress, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	var ledger *iota_sdk.Ledger
	if _, ok := os.LookupEnv("LEDGER_SIMULATOR"); ok {
		ledger = iota_sdk.LedgerSpeculos("127.0.0.1", 9999)
	} else {
		ledger, err = iota_sdk.LedgerNativeHid()
		if err != nil {
			log.Fatalf("Failed to connect to the Ledger device: %v", err)
		}
	}
	if err := ledger.OpenApp(); err != nil {
		log.Fatalf("Failed to open the IOTA app: %v", err)
	}
	signer, err := ledger.Signer("m/44'/4218'/0'/0'/0'")
	if err != nil {
		log.Fatalf("Failed to create the signer: %v", err)
	}
	senderAddress := signer.Address()
	log.Printf("Sender address: %s", senderAddress)

	client, err := iota_sdk.GraphQlClientNewLocalnet()
	if err != nil {
		log.Fatalf("Failed to create GraphQL client: %v", err)
	}

	// Request funds from faucet
	if _, err := iota_sdk.FaucetClientNewLocalnet().RequestAndWaitForFinalized(senderAddress, client); err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	builder := client.TransactionBuilder(senderAddress)
	builder.SendIota(recipientAddress, iota_sdk.PtbArgumentU64(amount))

	// The builder passes the signer the coins the transaction spends, so the
	// device shows the transfer instead of asking to blind-sign
	log.Print("Review and approve the transaction on the device")
	waitFor := iota_sdk.WaitForTransactionFinalized
	effects, err := builder.Execute(iota_sdk.TransactionSignerFromLedger(signer), &waitFor)
	if err != nil {
		log.Fatalf("Failed to execute: %v", err)
	}
	log.Printf("Digest: %s", (*effects).Digest().ToBase58())
	log.Printf("Transaction status: %v", (*effects).AsV1().Status())
}
