package common

import (
	sdk "bindings/iota_sdk_ffi"
)

func IsClientErr(err error) bool {
	if sdkErr, ok := err.(*sdk.SdkFfiError); ok {
		return sdkErr == nil
	}
	return false
}
