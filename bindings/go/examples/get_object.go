// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func isNilError(err error) bool {
	if sdkErr, ok := err.(*sdk.SdkFfiError); ok {
		return sdkErr == nil
	}
	return false
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	objectID, err := sdk.ObjectIdFromHex("0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e")
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}

	objOpt, err := client.Object(objectID, nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get object contents: %v", err)
	}
	if objOpt == nil {
		log.Fatal("Missing object")
	}
	obj := *objOpt

	objType := "Package"
	if obj.ObjectType().IsStruct() { 
		objType = obj.ObjectType().AsStruct().String()
	}

	objOwner := "Immutable"
	if obj.Owner().IsAddress() {
		objOwner = fmt.Sprintf("Address(%v)", obj.Owner().AsAddress().ToHex())
	} else if obj.Owner().IsObject() {
		objOwner = fmt.Sprintf("Object(%v)", obj.Owner().AsObject().ToHex())
	} else if obj.Owner().IsShared() {
		objOwner = fmt.Sprintf("Shared(%v)", obj.Owner().AsShared())
	}

	fmt.Println("Object ID:", obj.ObjectId().ToHex())
    fmt.Println("Version:", obj.Version())
    fmt.Println("Previous transaction:", obj.PreviousTransaction().ToBase58())
    fmt.Println("Owner:", objOwner)
    fmt.Println("Storage rebate:", obj.StorageRebate())
    fmt.Println("Type:", objType)
    fmt.Println("BCS bytes:", hex.EncodeToString(obj.AsStruct().Contents))

}
