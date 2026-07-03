// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func objIdFromHex(hex string) *iota_sdk.ObjectId {
	id, err := iota_sdk.ObjectIdFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	return id
}

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	objectID := objIdFromHex("0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")

	objOpt, err := client.Object(objectID, nil)
	if err != nil {
		log.Fatalf("Failed to get object contents: %v", err)
	}
	if objOpt == nil {
		log.Fatal("Missing object")
	}
	obj := *objOpt

	fmt.Println("Object ID:", obj.Id().ToHex())
	fmt.Println("Version:", obj.Version())
	fmt.Println("Previous transaction:", obj.PreviousTransaction().ToBase58())
	fmt.Println("Owner:", obj.Owner())
	fmt.Println("Storage rebate:", obj.StorageRebate())
	fmt.Println("Type:", obj.ObjectType())
	fmt.Println("BCS bytes:", iota_sdk.HexEncode(obj.AsStruct().Contents))

}
