// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	stakedIotaType := "0x3::staking_pool::StakedIota"
	stakedIotas, err := client.Objects(&iota_sdk.ObjectFilter{TypeTag: &stakedIotaType}, nil)
	if err != nil {
		log.Fatalf("Failed to get staked iota: %v", err)
	}

	if len(stakedIotas.Data) == 0 {
		fmt.Println("No StakedIota objects found")
	} else {
		fmt.Println("StakedIota object IDs:")
		for _, stakedIota := range stakedIotas.Data {
			fmt.Printf("%s\n", stakedIota.Id().ToHex())
		}
	}
}
