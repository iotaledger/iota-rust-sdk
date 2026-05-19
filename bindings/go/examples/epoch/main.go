// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	// Get current epoch
	currentEpoch, err := client.Epoch(nil)
	if err != nil {
		log.Fatalf("Failed to get current epoch: %v", err)
	}
	if currentEpoch == nil {
		log.Fatal("Current epoch is nil")
	}

	fmt.Printf("Current epoch: %d\n", currentEpoch.EpochId)
	fmt.Printf("Current epoch start time: %d\n", currentEpoch.StartTimestamp)

	// Get previous epoch (skip on epoch 0)
	if currentEpoch.EpochId == 0 {
		fmt.Println("No previous epoch (current is epoch 0)")
		return
	}
	previousEpochId := currentEpoch.EpochId - 1
	previousEpoch, err := client.Epoch(&previousEpochId)
	if err != nil {
		log.Fatalf("Failed to get previous epoch: %v", err)
	}
	if previousEpoch == nil {
		log.Fatal("Previous epoch is nil")
	}

	fmt.Printf("Previous epoch: %d\n", previousEpoch.EpochId)
	if previousEpoch.TotalStakeRewards != nil {
		fmt.Printf("Previous epoch stake rewards: %s\n", *previousEpoch.TotalStakeRewards)
	} else {
		fmt.Println("Previous epoch stake rewards: <none>")
	}
}
