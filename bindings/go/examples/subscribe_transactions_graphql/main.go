// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Tail transactions as they are executed, over a GraphQL subscription.
//
// Unlike the paginated queries, a subscription never ends on its own: it is
// pulled one update at a time and stopped with Cancel. Localnet may be idle,
// so the example asks the faucet for coins to generate a transaction, and
// cancels after a deadline so it cannot hang.

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

const deadline = 60 * time.Second

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()
	kind := iota_sdk.TransactionBlockKindInputProgrammableTx
	subscription := client.TransactionsSubscription(&iota_sdk.SubscriptionTransactionFilter{Kind: &kind}, nil)
	defer subscription.Cancel()

	// Cancelling unblocks a pending Next, which is what keeps the example from
	// waiting forever on a network that produces nothing.
	go func() {
		time.Sleep(deadline)
		subscription.Cancel()
	}()

	go func() {
		// Give the subscription a moment to connect before generating activity,
		// otherwise the transaction lands before anyone is listening.
		time.Sleep(2 * time.Second)
		address, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
		if err != nil {
			log.Fatalf("Failed to create address: %v", err)
		}
		if _, err := iota_sdk.FaucetClientNewLocalnet().RequestAndWait(address); err != nil {
			log.Fatalf("Failed to request faucet: %v", err)
		}
	}()

	fmt.Println("Waiting for a transaction...")
	for {
		update, err := subscription.Next()
		if err != nil {
			log.Fatalf("Subscription failed: %v", err)
		}
		if update == nil {
			fmt.Printf("No transaction observed within %s\n", deadline)
			os.Exit(1)
		}

		switch update := (*update).(type) {
		case iota_sdk.TransactionUpdateTransaction:
			transaction := update.Transaction.Transaction
			fmt.Println("Digest: ", transaction.Digest().ToBase58())
			fmt.Println("Sender: ", transaction.Sender().ToHex())
			return
		case iota_sdk.TransactionUpdateInterrupted:
			// Delivery recovers on its own; items in the gap may be missed.
			fmt.Println("Interrupted: ", update.Message)
		}
	}
}
