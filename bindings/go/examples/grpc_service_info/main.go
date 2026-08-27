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

	info, err := client.GetServiceInfo(nil)
	if err != nil {
		log.Fatalf("Failed to get service info: %v", err)
	}
	if info.ChainId != nil {
		fmt.Println("Chain ID:", *info.ChainId)
	}
	if info.Epoch != nil {
		fmt.Println("Epoch:", *info.Epoch)
	}
	if info.CheckpointHeight != nil {
		fmt.Println("Checkpoint height:", *info.CheckpointHeight)
	}

	gasPrice, err := client.GetReferenceGasPrice()
	if err != nil {
		log.Fatalf("Failed to get reference gas price: %v", err)
	}
	fmt.Println("Reference gas price:", gasPrice)
}
