// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
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

	obj, err := client.MoveObjectContents(objectID, nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get object contents: %v", err)
	}

	var objJson interface{}
	jsonErr := json.Unmarshal([]byte(*obj), &objJson)
	if jsonErr != nil {
		log.Fatalf("Failed to get object json: %v", err)
	}
	objJsonMap := objJson.(map[string]interface{})

	fmt.Println("Domain:", objJsonMap["domain_name"])
}
