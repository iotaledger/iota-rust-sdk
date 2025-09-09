// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"bindings/common"
	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	// Get current epoch
	currentEpoch, err := client.Epoch(nil)
	if !common.IsClientErr(err) {
		log.Fatalf("Failed to get current epoch: %v", err)
	}
	if currentEpoch == nil {
		log.Fatal("Current epoch is nil")
	}

	fmt.Printf("Current epoch: %d\n", currentEpoch.EpochId)
	fmt.Printf("Current epoch start time: %d\n", currentEpoch.StartTimestamp)

	// Get previous epoch
	previousEpochId := currentEpoch.EpochId - 1
	previousEpoch, err := client.Epoch(&previousEpochId)
	if !common.IsClientErr(err) {
		log.Fatalf("Failed to get previous epoch: %v", err)
	}
	if previousEpoch == nil {
		log.Fatal("Previous epoch is nil")
	}

	fmt.Printf("Previous epoch: %d\n", previousEpoch.EpochId)
	if previousEpoch.TotalStakeRewards != nil {
		fmt.Printf("Previous epoch stake rewards: %s\n", *previousEpoch.TotalStakeRewards)
	}
}
