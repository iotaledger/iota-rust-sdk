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

	objectID, err := iota_sdk.ObjectIdFromHex("0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}

	// `Objects` is batched: it takes a list of ids and returns the objects in
	// the same order.
	objects, err := client.Objects([]*iota_sdk.ObjectId{objectID})
	if err != nil {
		log.Fatalf("Failed to get object: %v", err)
	}
	obj := objects[0]

	fmt.Println("Object ID:", obj.Id().ToHex())
	fmt.Println("Version:", obj.Version())
	fmt.Println("Previous transaction:", obj.PreviousTransaction().ToBase58())
	fmt.Println("Owner:", obj.Owner())
	fmt.Println("Storage rebate:", obj.StorageRebate())
	fmt.Println("Type:", obj.ObjectType())
	fmt.Println("BCS bytes:", iota_sdk.HexEncode(obj.AsStruct().Contents))
}
