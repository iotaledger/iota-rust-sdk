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

	address, err := iota_sdk.AddressFromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWaitForFinalized(address, client)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	coins, err := client.Coins(address, nil, nil)
	if err != nil {
		log.Fatalf("Failed to fetch coins: %v", err)
	}
	if len(coins.Data) == 0 {
		log.Fatal("address has no coins after faucet request")
	}
	objectID := coins.Data[0].Id()

	objOpt, err := client.Object(objectID, nil)
	if err != nil {
		log.Fatalf("Failed to get object contents: %v", err)
	}
	if objOpt == nil {
		log.Fatal("Missing object")
	}
	obj := *objOpt

	fmt.Println("Object ID:", obj.ObjectId().ToHex())
	fmt.Println("Version:", obj.Version())
	fmt.Println("Previous transaction:", obj.PreviousTransaction().ToBase58())
	fmt.Println("Owner:", obj.Owner())
	fmt.Println("Storage rebate:", obj.StorageRebate())
	fmt.Println("Type:", obj.ObjectType())
	fmt.Println("BCS bytes:", iota_sdk.HexEncode(obj.AsStruct().Contents))

}
