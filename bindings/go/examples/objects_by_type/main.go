// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	stakedIotaType := "0x3::staking_pool::StakedIota"
	stakedIotas, err := client.Objects(&sdk.ObjectFilter{TypeTag: &stakedIotaType}, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get staked iota: %v", err)
	}

	if len(stakedIotas.Data) == 0 {
		fmt.Println("No StakedIota objects found")
	} else {
		fmt.Println("StakedIota object IDs:")
		for _, stakedIota := range stakedIotas.Data {
			fmt.Printf("%s\n", stakedIota.ObjectId().ToHex())
		}
	}
}
