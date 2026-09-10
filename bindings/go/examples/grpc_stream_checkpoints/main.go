// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client, err := iota_sdk.GrpcClientNewTestnet()
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	// Pick a small range of recent checkpoints to stream.
	latest, err := client.GetCheckpointLatest(nil, nil, nil)
	if err != nil {
		log.Fatalf("Failed to get latest checkpoint: %v", err)
	}
	start := latest.SequenceNumber - 4

	stream, err := client.StreamCheckpoints(&start, &latest.SequenceNumber, nil, nil, nil)
	if err != nil {
		log.Fatalf("Failed to open checkpoint stream: %v", err)
	}

	for {
		checkpoint, err := stream.Next()
		if err != nil {
			log.Fatalf("Failed to get next checkpoint: %v", err)
		}
		if checkpoint == nil {
			break
		}
		summary := *checkpoint.Summary
		fmt.Printf("Checkpoint %d: epoch %d, %d total transactions, timestamp %d\n",
			checkpoint.SequenceNumber,
			summary.Epoch(),
			summary.NetworkTotalTransactions(),
			summary.TimestampMs())
	}
}
