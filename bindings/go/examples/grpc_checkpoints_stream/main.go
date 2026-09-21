// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

const howMany uint64 = 5

func main() {
	client, err := iota_sdk.GrpcClientNewTestnet()
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	// Pick a starting point a few checkpoints behind head so the example
	// returns promptly instead of waiting on new blocks.
	latest, err := client.CheckpointLatest(nil, nil, nil)
	if err != nil {
		log.Fatalf("Failed to get latest checkpoint: %v", err)
	}
	head := latest.SequenceNumber
	start := uint64(0)
	if head >= howMany-1 {
		start = head - (howMany - 1)
	}
	end := head

	// Only ask for the summary — keeps the message small. Pass nil (or
	// compose more fields) to pull more data per checkpoint.
	readMask := []string{"checkpoint.summary"}
	stream, err := client.CheckpointsStream(&start, &end, nil, nil, &readMask)
	if err != nil {
		log.Fatalf("Failed to open checkpoint stream: %v", err)
	}

	fmt.Printf("Streaming checkpoints %d..=%d\n", start, end)
	for {
		checkpoint, err := stream.Next()
		if err != nil {
			log.Fatalf("Failed to get next checkpoint: %v", err)
		}
		if checkpoint == nil {
			break
		}
		if checkpoint.Summary == nil {
			log.Fatalf("Checkpoint %d has no summary", checkpoint.SequenceNumber)
		}
		summary := *checkpoint.Summary
		fmt.Printf("  cp %6d  epoch %3d  txs %4d  ts %d\n",
			checkpoint.SequenceNumber,
			summary.Epoch(),
			summary.NetworkTotalTransactions(),
			summary.TimestampMs())
	}
}
