// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	sdk "bindings/iota_sdk"
)

func objIdFromHex(hex string) *sdk.ObjectId {
	id, err := sdk.ObjectIdFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	return id
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	objectID := objIdFromHex("0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e")

	objOpt, err := client.Object(objectID, nil)
	if err.(*sdk.SdkFfiError) != nil {
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
	fmt.Println("BCS bytes:", sdk.HexEncode(obj.AsStruct().Contents))

}
