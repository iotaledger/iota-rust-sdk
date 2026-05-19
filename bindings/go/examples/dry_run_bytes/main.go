// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

// A pre-encoded programmable transaction calling `0x1::u64::max(1, 2)` with
// empty gas-payment objects. Because the bytes do not reference any on-chain
// object refs, they stay valid across networks — the dry-run endpoint fills in
// gas coins on demand.
const txBytesBase64 = "AAACAAgBAAAAAAAAAAAIAgAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA3U2NANtYXgAAgEAAAEBACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUiACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUi6AMAAAAAAAAAAAAAAAAAAAA="

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	transaction, err := iota_sdk.TransactionFromBase64(txBytesBase64)
	if err != nil {
		log.Fatalf("Failed to parse transaction: %v", err)
	}

	res, err := client.DryRunTx(transaction, false)
	if err != nil {
		log.Fatalf("Failed to dry run transaction: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Dry run failed: %v", *res.Error)
	}

	log.Print("Dry run was successful!")
	log.Printf("Dry run result: %+v", res)
}
