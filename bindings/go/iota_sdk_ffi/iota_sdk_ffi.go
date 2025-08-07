
package iota_sdk_ffi

// #include <iota_sdk_ffi.h>
import "C"

import (
	"bytes"
	"fmt"
	"io"
	"unsafe"
	"encoding/binary"
	"runtime/cgo"
	"math"
	"runtime"
	"sync/atomic"
)



// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromExternal(b RustBufferI) GoRustBuffer {
	return GoRustBuffer {
		inner: C.RustBuffer {
			capacity: C.uint64_t(b.Capacity()),
			len: C.uint64_t(b.Len()),
			data: (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func( status *C.RustCallStatus) bool {
		C.ffi_iota_sdk_ffi_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}


func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes {
		len: C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func( status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_iota_sdk_ffi_rustbuffer_from_bytes(foreign, status)
	})
}


type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}



func rustCallWithError[E any, U any](converter BufReader[*E], callback func(*C.RustCallStatus) U) (U, *E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[*E], status C.RustCallStatus) *E {
	switch status.code {
	case 0:
		return nil
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer { inner: status.errorBuf })
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer { inner: status.errorBuf })))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer {
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}


func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}


func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {
        
        uniffiCheckChecksums()
}


func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 29
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_iota_sdk_ffi_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: UniFFI contract version mismatch")
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_address_to_bytes()
	})
	if checksum != 57710 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_address_to_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_address_to_hex()
	})
	if checksum != 22032 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_address_to_hex: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_bls12381publickey_to_bytes()
	})
	if checksum != 9890 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_bls12381publickey_to_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_checkpointcommitment_as_ecmh_live_object_set_digest()
	})
	if checksum != 41616 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_checkpointcommitment_as_ecmh_live_object_set_digest: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_checkpointcommitment_is_ecmh_live_object_set()
	})
	if checksum != 22589 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_checkpointcommitment_is_ecmh_live_object_set: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_checkpointsummarypage_data()
	})
	if checksum != 44115 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_checkpointsummarypage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_checkpointsummarypage_is_empty()
	})
	if checksum != 48209 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_checkpointsummarypage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_checkpointsummarypage_page_info()
	})
	if checksum != 63456 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_checkpointsummarypage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_coin_balance()
	})
	if checksum != 29928 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_coin_balance: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_coin_coin_type()
	})
	if checksum != 18211 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_coin_coin_type: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_coin_id()
	})
	if checksum != 40013 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_coin_id: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_coinpage_data()
	})
	if checksum != 29556 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_coinpage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_coinpage_is_empty()
	})
	if checksum != 6966 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_coinpage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_coinpage_page_info()
	})
	if checksum != 50368 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_coinpage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_dynamicfieldoutputpage_data()
	})
	if checksum != 46262 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_dynamicfieldoutputpage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_dynamicfieldoutputpage_is_empty()
	})
	if checksum != 38341 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_dynamicfieldoutputpage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_dynamicfieldoutputpage_page_info()
	})
	if checksum != 21447 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_dynamicfieldoutputpage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_ed25519publickey_to_bytes()
	})
	if checksum != 16656 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_ed25519publickey_to_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_epochpage_data()
	})
	if checksum != 13705 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_epochpage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_epochpage_is_empty()
	})
	if checksum != 19239 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_epochpage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_epochpage_page_info()
	})
	if checksum != 57718 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_epochpage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_eventpage_data()
	})
	if checksum != 29547 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_eventpage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_eventpage_is_empty()
	})
	if checksum != 14566 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_eventpage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_eventpage_page_info()
	})
	if checksum != 27854 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_eventpage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_faucetclient_request()
	})
	if checksum != 13326 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_faucetclient_request: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_faucetclient_request_and_wait()
	})
	if checksum != 48304 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_faucetclient_request_and_wait: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_faucetclient_request_status()
	})
	if checksum != 42353 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_faucetclient_request_status: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_active_validators()
	})
	if checksum != 32356 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_active_validators: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_balance()
	})
	if checksum != 9953 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_balance: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_chain_id()
	})
	if checksum != 45619 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_chain_id: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_checkpoint()
	})
	if checksum != 33658 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_checkpoint: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_checkpoints()
	})
	if checksum != 37650 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_checkpoints: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_coin_metadata()
	})
	if checksum != 34454 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_coin_metadata: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_coins()
	})
	if checksum != 49561 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_coins: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dry_run_tx()
	})
	if checksum != 62890 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dry_run_tx: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dry_run_tx_kind()
	})
	if checksum != 47707 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dry_run_tx_kind: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_field()
	})
	if checksum != 8125 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_field: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_fields()
	})
	if checksum != 28199 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_fields: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_object_field()
	})
	if checksum != 23995 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_object_field: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch()
	})
	if checksum != 46788 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch_total_checkpoints()
	})
	if checksum != 29086 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch_total_checkpoints: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch_total_transaction_blocks()
	})
	if checksum != 61978 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch_total_transaction_blocks: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_events()
	})
	if checksum != 3400 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_events: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_execute_tx()
	})
	if checksum != 41079 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_execute_tx: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_latest_checkpoint_sequence_number()
	})
	if checksum != 40336 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_latest_checkpoint_sequence_number: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_max_page_size()
	})
	if checksum != 44733 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_max_page_size: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_move_object_contents()
	})
	if checksum != 40412 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_move_object_contents: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_move_object_contents_bcs()
	})
	if checksum != 49694 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_move_object_contents_bcs: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_normalized_move_function()
	})
	if checksum != 49066 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_normalized_move_function: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_normalized_move_module()
	})
	if checksum != 6413 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_normalized_move_module: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_object()
	})
	if checksum != 51508 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_object: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_object_bcs()
	})
	if checksum != 1970 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_object_bcs: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_objects()
	})
	if checksum != 49764 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_objects: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package()
	})
	if checksum != 7913 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package_latest()
	})
	if checksum != 55024 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package_latest: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package_versions()
	})
	if checksum != 23726 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package_versions: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_packages()
	})
	if checksum != 53612 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_packages: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_protocol_config()
	})
	if checksum != 23389 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_protocol_config: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_reference_gas_price()
	})
	if checksum != 39065 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_reference_gas_price: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_service_config()
	})
	if checksum != 24210 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_service_config: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_set_rpc_server()
	})
	if checksum != 31958 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_set_rpc_server: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_supply()
	})
	if checksum != 21504 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_supply: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks()
	})
	if checksum != 9583 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks_by_digest()
	})
	if checksum != 64969 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks_by_digest: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks_by_seq_num()
	})
	if checksum != 18624 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks_by_seq_num: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction()
	})
	if checksum != 54687 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction_data_effects()
	})
	if checksum != 57979 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction_data_effects: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction_effects()
	})
	if checksum != 56760 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction_effects: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions()
	})
	if checksum != 29564 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions_data_effects()
	})
	if checksum != 61098 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions_data_effects: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions_effects()
	})
	if checksum != 56867 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions_effects: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_movepackagepage_data()
	})
	if checksum != 63718 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_movepackagepage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_movepackagepage_is_empty()
	})
	if checksum != 64716 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_movepackagepage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_movepackagepage_page_info()
	})
	if checksum != 5493 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_movepackagepage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_object_as_struct()
	})
	if checksum != 2473 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_object_as_struct: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_object_data()
	})
	if checksum != 4330 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_object_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_object_object_id()
	})
	if checksum != 6575 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_object_object_id: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_object_object_type()
	})
	if checksum != 1843 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_object_object_type: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_object_owner()
	})
	if checksum != 3724 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_object_owner: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_object_previous_transaction()
	})
	if checksum != 455 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_object_previous_transaction: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_object_storage_rebate()
	})
	if checksum != 24969 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_object_storage_rebate: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_object_version()
	})
	if checksum != 18433 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_object_version: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_objectid_to_address()
	})
	if checksum != 21880 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_objectid_to_address: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_objectid_to_bytes()
	})
	if checksum != 38367 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_objectid_to_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_objectid_to_hex()
	})
	if checksum != 4418 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_objectid_to_hex: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_objectpage_data()
	})
	if checksum != 3639 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_objectpage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_objectpage_is_empty()
	})
	if checksum != 56778 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_objectpage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_objectpage_page_info()
	})
	if checksum != 10226 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_objectpage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_secp256k1publickey_to_bytes()
	})
	if checksum != 49170 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_secp256k1publickey_to_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_secp256r1publickey_to_bytes()
	})
	if checksum != 21066 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_secp256r1publickey_to_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_signedtransaction_signatures()
	})
	if checksum != 59055 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_signedtransaction_signatures: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_signedtransaction_transaction()
	})
	if checksum != 60873 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_signedtransaction_transaction: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_signedtransactionpage_data()
	})
	if checksum != 7316 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_signedtransactionpage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_signedtransactionpage_is_empty()
	})
	if checksum != 52119 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_signedtransactionpage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_signedtransactionpage_page_info()
	})
	if checksum != 4757 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_signedtransactionpage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transaction_expiration()
	})
	if checksum != 4282 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transaction_expiration: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transaction_gas_payment()
	})
	if checksum != 5316 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transaction_gas_payment: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transaction_kind()
	})
	if checksum != 49492 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transaction_kind: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transaction_sender()
	})
	if checksum != 38190 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transaction_sender: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transactiondataeffects_effects()
	})
	if checksum != 62613 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transactiondataeffects_effects: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transactiondataeffects_tx()
	})
	if checksum != 13303 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transactiondataeffects_tx: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transactiondataeffectspage_data()
	})
	if checksum != 63792 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transactiondataeffectspage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transactiondataeffectspage_is_empty()
	})
	if checksum != 31504 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transactiondataeffectspage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transactiondataeffectspage_page_info()
	})
	if checksum != 59789 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transactiondataeffectspage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transactioneffectspage_data()
	})
	if checksum != 20040 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transactioneffectspage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transactioneffectspage_is_empty()
	})
	if checksum != 19615 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transactioneffectspage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_transactioneffectspage_page_info()
	})
	if checksum != 44668 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_transactioneffectspage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_validatorpage_data()
	})
	if checksum != 23633 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_validatorpage_data: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_validatorpage_is_empty()
	})
	if checksum != 5938 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_validatorpage_is_empty: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_method_validatorpage_page_info()
	})
	if checksum != 50813 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_method_validatorpage_page_info: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_address_from_bytes()
	})
	if checksum != 58901 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_address_from_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_address_from_hex()
	})
	if checksum != 63442 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_address_from_hex: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_address_generate()
	})
	if checksum != 48865 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_address_generate: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_from_bytes()
	})
	if checksum != 6069 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_from_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_from_str()
	})
	if checksum != 26128 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_from_str: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_generate()
	})
	if checksum != 30791 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_generate: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_coin_try_from_object()
	})
	if checksum != 35349 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_coin_try_from_object: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_from_bytes()
	})
	if checksum != 60403 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_from_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_from_str()
	})
	if checksum != 38751 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_from_str: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_generate()
	})
	if checksum != 46412 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_generate: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_authenticator_state_create()
	})
	if checksum != 18946 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_authenticator_state_create: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_authenticator_state_expire()
	})
	if checksum != 49861 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_authenticator_state_expire: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_change_epoch()
	})
	if checksum != 16640 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_change_epoch: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_change_epoch_v2()
	})
	if checksum != 17262 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_change_epoch_v2: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_devnet()
	})
	if checksum != 37366 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_devnet: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_local()
	})
	if checksum != 55393 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_local: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_new()
	})
	if checksum != 13557 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_new: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_testnet()
	})
	if checksum != 16109 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_testnet: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new()
	})
	if checksum != 32097 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_devnet()
	})
	if checksum != 6494 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_devnet: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_localhost()
	})
	if checksum != 5570 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_localhost: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_mainnet()
	})
	if checksum != 3613 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_mainnet: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_testnet()
	})
	if checksum != 48529 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_testnet: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_object_new()
	})
	if checksum != 56232 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_object_new: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_objectid_from_bytes()
	})
	if checksum != 41789 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_objectid_from_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_objectid_from_hex()
	})
	if checksum != 30954 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_objectid_from_hex: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_from_bytes()
	})
	if checksum != 20339 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_from_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_from_str()
	})
	if checksum != 24158 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_from_str: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_generate()
	})
	if checksum != 36411 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_generate: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_from_bytes()
	})
	if checksum != 60002 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_from_bytes: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_from_str()
	})
	if checksum != 27991 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_from_str: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_generate()
	})
	if checksum != 49992 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_generate: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_signedtransaction_new()
	})
	if checksum != 6988 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_signedtransaction_new: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_transaction_new()
	})
	if checksum != 36271 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_transaction_new: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_transactiondataeffects_new()
	})
	if checksum != 30302 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_transactiondataeffects_new: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_authenticator_state_update_v1()
	})
	if checksum != 37860 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_authenticator_state_update_v1: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_consensus_commit_prologue_v1()
	})
	if checksum != 50635 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_consensus_commit_prologue_v1: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_end_of_epoch()
	})
	if checksum != 65525 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_end_of_epoch: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_genesis()
	})
	if checksum != 65272 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_genesis: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_programmable_transaction()
	})
	if checksum != 51205 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_programmable_transaction: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_randomness_state_update()
	})
	if checksum != 45772 {
		// If this happens try cleaning and rebuilding your project
		panic("iota_sdk_ffi: uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_randomness_state_update: UniFFI API checksum mismatch")
	}
	}
}



type FfiConverterInt32 struct{}

var FfiConverterInt32INSTANCE = FfiConverterInt32{}

func (FfiConverterInt32) Lower(value int32) C.int32_t {
	return C.int32_t(value)
}

func (FfiConverterInt32) Write(writer io.Writer, value int32) {
	writeInt32(writer, value)
}

func (FfiConverterInt32) Lift(value C.int32_t) int32 {
	return int32(value)
}

func (FfiConverterInt32) Read(reader io.Reader) int32 {
	return readInt32(reader)
}

type FfiDestroyerInt32 struct {}

func (FfiDestroyerInt32) Destroy(_ int32) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct {}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterInt64 struct{}

var FfiConverterInt64INSTANCE = FfiConverterInt64{}

func (FfiConverterInt64) Lower(value int64) C.int64_t {
	return C.int64_t(value)
}

func (FfiConverterInt64) Write(writer io.Writer, value int64) {
	writeInt64(writer, value)
}

func (FfiConverterInt64) Lift(value C.int64_t) int64 {
	return int64(value)
}

func (FfiConverterInt64) Read(reader io.Reader) int64 {
	return readInt64(reader)
}

type FfiDestroyerInt64 struct {}

func (FfiDestroyerInt64) Destroy(_ int64) {}

type FfiConverterBool struct{}

var FfiConverterBoolINSTANCE = FfiConverterBool{}

func (FfiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (FfiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (FfiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (FfiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type FfiDestroyerBool struct {}

func (FfiDestroyerBool) Destroy(_ bool) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct {}

func (FfiDestroyerString) Destroy(_ string) {}

type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) C.RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type FfiDestroyerBytes struct {}

func (FfiDestroyerBytes) Destroy(_ []byte) {}


// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	pointer unsafe.Pointer
	callCounter atomic.Int64
	cloneFunction func(unsafe.Pointer, *C.RustCallStatus) unsafe.Pointer
	freeFunction func(unsafe.Pointer, *C.RustCallStatus)
	destroyed atomic.Bool
}

func newFfiObject(
	pointer unsafe.Pointer,
	cloneFunction func(unsafe.Pointer, *C.RustCallStatus) unsafe.Pointer,
	freeFunction func(unsafe.Pointer, *C.RustCallStatus),
) FfiObject {
	return FfiObject {
		pointer: pointer,
		cloneFunction: cloneFunction,
		freeFunction: freeFunction,
	}
}

func (ffiObject *FfiObject)incrementPointer(debugName string) unsafe.Pointer {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter + 1) {
			break
		}
	}

	return rustCall(func(status *C.RustCallStatus) unsafe.Pointer {
		return ffiObject.cloneFunction(ffiObject.pointer, status)
	})
}

func (ffiObject *FfiObject)decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject)destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject)freeRustArcPtr() {
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.pointer, status)
		return 0
	})
}
// Unique identifier for an Account on the IOTA blockchain.
//
// An `Address` is a 32-byte pseudonymous identifier used to uniquely identify
// an account and asset-ownership on the IOTA blockchain. Often, human-readable
// addresses are encoded in hexadecimal with a `0x` prefix. For example, this
// is a valid IOTA address:
// `0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331`.
//
// ```
// use iota_types::Address;
//
// let hex = "0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331";
// let address = Address::from_hex(hex).unwrap();
// println!("Address: {}", address);
// assert_eq!(hex, address.to_string());
// ```
//
// # Deriving an Address
//
// Addresses are cryptographically derived from a number of user account
// authenticators, the simplest of which is an
// [`Ed25519PublicKey`](iota_types::Ed25519PublicKey).
//
// Deriving an address consists of the Blake2b256 hash of the sequence of bytes
// of its corresponding authenticator, prefixed with a domain-separator (except
// ed25519, for compatability reasons). For each other authenticator, this
// domain-separator is the single byte-value of its
// [`SignatureScheme`](iota_types::SignatureScheme) flag. E.g. `hash(signature
// schema flag || authenticator bytes)`.
//
// Each authenticator has a method for deriving its `Address` as well as
// documentation for the specifics of how the derivation is done. See
// [`Ed25519PublicKey::derive_address`] for an example.
//
// [`Ed25519PublicKey::derive_address`]: iota_types::Ed25519PublicKey::derive_address
//
// ## Relationship to ObjectIds
//
// [`ObjectId`]s and [`Address`]es share the same 32-byte addressable space but
// are derived leveraging different domain-separator values to ensure that,
// cryptographically, there won't be any overlap, e.g. there can't be a
// valid `Object` who's `ObjectId` is equal to that of the `Address` of a user
// account.
//
// [`ObjectId`]: iota_types::ObjectId
//
// # BCS
//
// An `Address`'s BCS serialized form is defined by the following:
//
// ```text
// address = 32OCTET
// ```
type AddressInterface interface {
	ToBytes() []byte
	ToHex() string
}
// Unique identifier for an Account on the IOTA blockchain.
//
// An `Address` is a 32-byte pseudonymous identifier used to uniquely identify
// an account and asset-ownership on the IOTA blockchain. Often, human-readable
// addresses are encoded in hexadecimal with a `0x` prefix. For example, this
// is a valid IOTA address:
// `0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331`.
//
// ```
// use iota_types::Address;
//
// let hex = "0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331";
// let address = Address::from_hex(hex).unwrap();
// println!("Address: {}", address);
// assert_eq!(hex, address.to_string());
// ```
//
// # Deriving an Address
//
// Addresses are cryptographically derived from a number of user account
// authenticators, the simplest of which is an
// [`Ed25519PublicKey`](iota_types::Ed25519PublicKey).
//
// Deriving an address consists of the Blake2b256 hash of the sequence of bytes
// of its corresponding authenticator, prefixed with a domain-separator (except
// ed25519, for compatability reasons). For each other authenticator, this
// domain-separator is the single byte-value of its
// [`SignatureScheme`](iota_types::SignatureScheme) flag. E.g. `hash(signature
// schema flag || authenticator bytes)`.
//
// Each authenticator has a method for deriving its `Address` as well as
// documentation for the specifics of how the derivation is done. See
// [`Ed25519PublicKey::derive_address`] for an example.
//
// [`Ed25519PublicKey::derive_address`]: iota_types::Ed25519PublicKey::derive_address
//
// ## Relationship to ObjectIds
//
// [`ObjectId`]s and [`Address`]es share the same 32-byte addressable space but
// are derived leveraging different domain-separator values to ensure that,
// cryptographically, there won't be any overlap, e.g. there can't be a
// valid `Object` who's `ObjectId` is equal to that of the `Address` of a user
// account.
//
// [`ObjectId`]: iota_types::ObjectId
//
// # BCS
//
// An `Address`'s BCS serialized form is defined by the following:
//
// ```text
// address = 32OCTET
// ```
type Address struct {
	ffiObject FfiObject
}


func AddressFromBytes(bytes []byte) (*Address, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_address_from_bytes(FfiConverterBytesINSTANCE.Lower(bytes),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Address
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterAddressINSTANCE.Lift(_uniffiRV), nil
		}
}

func AddressFromHex(hex string) (*Address, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_address_from_hex(FfiConverterStringINSTANCE.Lower(hex),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Address
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterAddressINSTANCE.Lift(_uniffiRV), nil
		}
}

func AddressGenerate() *Address {
	return FfiConverterAddressINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_address_generate(_uniffiStatus)
	}))
}



func (_self *Address) ToBytes() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Address")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_address_to_bytes(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *Address) ToHex() string {
	_pointer := _self.ffiObject.incrementPointer("*Address")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_address_to_hex(
		_pointer,_uniffiStatus),
	}
	}))
}
func (object *Address) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterAddress struct {}

var FfiConverterAddressINSTANCE = FfiConverterAddress{}


func (c FfiConverterAddress) Lift(pointer unsafe.Pointer) *Address {
	result := &Address {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_address(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_address(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Address).Destroy)
	return result
}

func (c FfiConverterAddress) Read(reader io.Reader) *Address {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterAddress) Lower(value *Address) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Address")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterAddress) Write(writer io.Writer, value *Address) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerAddress struct {}

func (_ FfiDestroyerAddress) Destroy(value *Address) {
		value.Destroy()
}



type AuthenticatorStateExpireInterface interface {
}
type AuthenticatorStateExpire struct {
	ffiObject FfiObject
}



func (object *AuthenticatorStateExpire) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterAuthenticatorStateExpire struct {}

var FfiConverterAuthenticatorStateExpireINSTANCE = FfiConverterAuthenticatorStateExpire{}


func (c FfiConverterAuthenticatorStateExpire) Lift(pointer unsafe.Pointer) *AuthenticatorStateExpire {
	result := &AuthenticatorStateExpire {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_authenticatorstateexpire(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_authenticatorstateexpire(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*AuthenticatorStateExpire).Destroy)
	return result
}

func (c FfiConverterAuthenticatorStateExpire) Read(reader io.Reader) *AuthenticatorStateExpire {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterAuthenticatorStateExpire) Lower(value *AuthenticatorStateExpire) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*AuthenticatorStateExpire")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterAuthenticatorStateExpire) Write(writer io.Writer, value *AuthenticatorStateExpire) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerAuthenticatorStateExpire struct {}

func (_ FfiDestroyerAuthenticatorStateExpire) Destroy(value *AuthenticatorStateExpire) {
		value.Destroy()
}



type AuthenticatorStateUpdateV1Interface interface {
}
type AuthenticatorStateUpdateV1 struct {
	ffiObject FfiObject
}



func (object *AuthenticatorStateUpdateV1) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterAuthenticatorStateUpdateV1 struct {}

var FfiConverterAuthenticatorStateUpdateV1INSTANCE = FfiConverterAuthenticatorStateUpdateV1{}


func (c FfiConverterAuthenticatorStateUpdateV1) Lift(pointer unsafe.Pointer) *AuthenticatorStateUpdateV1 {
	result := &AuthenticatorStateUpdateV1 {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_authenticatorstateupdatev1(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_authenticatorstateupdatev1(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*AuthenticatorStateUpdateV1).Destroy)
	return result
}

func (c FfiConverterAuthenticatorStateUpdateV1) Read(reader io.Reader) *AuthenticatorStateUpdateV1 {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterAuthenticatorStateUpdateV1) Lower(value *AuthenticatorStateUpdateV1) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*AuthenticatorStateUpdateV1")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterAuthenticatorStateUpdateV1) Write(writer io.Writer, value *AuthenticatorStateUpdateV1) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerAuthenticatorStateUpdateV1 struct {}

func (_ FfiDestroyerAuthenticatorStateUpdateV1) Destroy(value *AuthenticatorStateUpdateV1) {
		value.Destroy()
}



type BatchSendStatusInterface interface {
}
type BatchSendStatus struct {
	ffiObject FfiObject
}



func (object *BatchSendStatus) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterBatchSendStatus struct {}

var FfiConverterBatchSendStatusINSTANCE = FfiConverterBatchSendStatus{}


func (c FfiConverterBatchSendStatus) Lift(pointer unsafe.Pointer) *BatchSendStatus {
	result := &BatchSendStatus {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_batchsendstatus(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_batchsendstatus(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*BatchSendStatus).Destroy)
	return result
}

func (c FfiConverterBatchSendStatus) Read(reader io.Reader) *BatchSendStatus {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterBatchSendStatus) Lower(value *BatchSendStatus) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*BatchSendStatus")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterBatchSendStatus) Write(writer io.Writer, value *BatchSendStatus) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerBatchSendStatus struct {}

func (_ FfiDestroyerBatchSendStatus) Destroy(value *BatchSendStatus) {
		value.Destroy()
}



// A bls12381 min-sig public key.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// bls-public-key = %x60 96OCTECT
// ```
//
// Due to historical reasons, even though a min-sig `Bls12381PublicKey` has a
// fixed-length of 96, IOTA's binary representation of a min-sig
// `Bls12381PublicKey` is prefixed with its length meaning its serialized
// binary form (in bcs) is 97 bytes long vs a more compact 96 bytes.
type Bls12381PublicKeyInterface interface {
	ToBytes() []byte
}
// A bls12381 min-sig public key.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// bls-public-key = %x60 96OCTECT
// ```
//
// Due to historical reasons, even though a min-sig `Bls12381PublicKey` has a
// fixed-length of 96, IOTA's binary representation of a min-sig
// `Bls12381PublicKey` is prefixed with its length meaning its serialized
// binary form (in bcs) is 97 bytes long vs a more compact 96 bytes.
type Bls12381PublicKey struct {
	ffiObject FfiObject
}


func Bls12381PublicKeyFromBytes(bytes []byte) (*Bls12381PublicKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_bls12381publickey_from_bytes(FfiConverterBytesINSTANCE.Lower(bytes),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Bls12381PublicKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterBls12381PublicKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

func Bls12381PublicKeyFromStr(s string) (*Bls12381PublicKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_bls12381publickey_from_str(FfiConverterStringINSTANCE.Lower(s),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Bls12381PublicKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterBls12381PublicKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

func Bls12381PublicKeyGenerate() *Bls12381PublicKey {
	return FfiConverterBls12381PublicKeyINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_bls12381publickey_generate(_uniffiStatus)
	}))
}



func (_self *Bls12381PublicKey) ToBytes() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Bls12381PublicKey")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_bls12381publickey_to_bytes(
		_pointer,_uniffiStatus),
	}
	}))
}
func (object *Bls12381PublicKey) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterBls12381PublicKey struct {}

var FfiConverterBls12381PublicKeyINSTANCE = FfiConverterBls12381PublicKey{}


func (c FfiConverterBls12381PublicKey) Lift(pointer unsafe.Pointer) *Bls12381PublicKey {
	result := &Bls12381PublicKey {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_bls12381publickey(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_bls12381publickey(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Bls12381PublicKey).Destroy)
	return result
}

func (c FfiConverterBls12381PublicKey) Read(reader io.Reader) *Bls12381PublicKey {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterBls12381PublicKey) Lower(value *Bls12381PublicKey) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Bls12381PublicKey")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterBls12381PublicKey) Write(writer io.Writer, value *Bls12381PublicKey) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerBls12381PublicKey struct {}

func (_ FfiDestroyerBls12381PublicKey) Destroy(value *Bls12381PublicKey) {
		value.Destroy()
}



type ChangeEpochInterface interface {
}
type ChangeEpoch struct {
	ffiObject FfiObject
}



func (object *ChangeEpoch) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterChangeEpoch struct {}

var FfiConverterChangeEpochINSTANCE = FfiConverterChangeEpoch{}


func (c FfiConverterChangeEpoch) Lift(pointer unsafe.Pointer) *ChangeEpoch {
	result := &ChangeEpoch {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_changeepoch(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_changeepoch(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ChangeEpoch).Destroy)
	return result
}

func (c FfiConverterChangeEpoch) Read(reader io.Reader) *ChangeEpoch {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterChangeEpoch) Lower(value *ChangeEpoch) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ChangeEpoch")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterChangeEpoch) Write(writer io.Writer, value *ChangeEpoch) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerChangeEpoch struct {}

func (_ FfiDestroyerChangeEpoch) Destroy(value *ChangeEpoch) {
		value.Destroy()
}



type ChangeEpochV2Interface interface {
}
type ChangeEpochV2 struct {
	ffiObject FfiObject
}



func (object *ChangeEpochV2) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterChangeEpochV2 struct {}

var FfiConverterChangeEpochV2INSTANCE = FfiConverterChangeEpochV2{}


func (c FfiConverterChangeEpochV2) Lift(pointer unsafe.Pointer) *ChangeEpochV2 {
	result := &ChangeEpochV2 {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_changeepochv2(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_changeepochv2(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ChangeEpochV2).Destroy)
	return result
}

func (c FfiConverterChangeEpochV2) Read(reader io.Reader) *ChangeEpochV2 {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterChangeEpochV2) Lower(value *ChangeEpochV2) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ChangeEpochV2")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterChangeEpochV2) Write(writer io.Writer, value *ChangeEpochV2) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerChangeEpochV2 struct {}

func (_ FfiDestroyerChangeEpochV2) Destroy(value *ChangeEpochV2) {
		value.Destroy()
}



type CheckpointCommitmentInterface interface {
	AsEcmhLiveObjectSetDigest() *Digest
	IsEcmhLiveObjectSet() bool
}
type CheckpointCommitment struct {
	ffiObject FfiObject
}




func (_self *CheckpointCommitment) AsEcmhLiveObjectSetDigest() *Digest {
	_pointer := _self.ffiObject.incrementPointer("*CheckpointCommitment")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterDigestINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_checkpointcommitment_as_ecmh_live_object_set_digest(
		_pointer,_uniffiStatus)
	}))
}

func (_self *CheckpointCommitment) IsEcmhLiveObjectSet() bool {
	_pointer := _self.ffiObject.incrementPointer("*CheckpointCommitment")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_checkpointcommitment_is_ecmh_live_object_set(
		_pointer,_uniffiStatus)
	}))
}
func (object *CheckpointCommitment) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterCheckpointCommitment struct {}

var FfiConverterCheckpointCommitmentINSTANCE = FfiConverterCheckpointCommitment{}


func (c FfiConverterCheckpointCommitment) Lift(pointer unsafe.Pointer) *CheckpointCommitment {
	result := &CheckpointCommitment {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_checkpointcommitment(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_checkpointcommitment(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*CheckpointCommitment).Destroy)
	return result
}

func (c FfiConverterCheckpointCommitment) Read(reader io.Reader) *CheckpointCommitment {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterCheckpointCommitment) Lower(value *CheckpointCommitment) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*CheckpointCommitment")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterCheckpointCommitment) Write(writer io.Writer, value *CheckpointCommitment) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerCheckpointCommitment struct {}

func (_ FfiDestroyerCheckpointCommitment) Destroy(value *CheckpointCommitment) {
		value.Destroy()
}



type CheckpointContentsDigestInterface interface {
}
type CheckpointContentsDigest struct {
	ffiObject FfiObject
}



func (object *CheckpointContentsDigest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterCheckpointContentsDigest struct {}

var FfiConverterCheckpointContentsDigestINSTANCE = FfiConverterCheckpointContentsDigest{}


func (c FfiConverterCheckpointContentsDigest) Lift(pointer unsafe.Pointer) *CheckpointContentsDigest {
	result := &CheckpointContentsDigest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_checkpointcontentsdigest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_checkpointcontentsdigest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*CheckpointContentsDigest).Destroy)
	return result
}

func (c FfiConverterCheckpointContentsDigest) Read(reader io.Reader) *CheckpointContentsDigest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterCheckpointContentsDigest) Lower(value *CheckpointContentsDigest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*CheckpointContentsDigest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterCheckpointContentsDigest) Write(writer io.Writer, value *CheckpointContentsDigest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerCheckpointContentsDigest struct {}

func (_ FfiDestroyerCheckpointContentsDigest) Destroy(value *CheckpointContentsDigest) {
		value.Destroy()
}



type CheckpointDigestInterface interface {
}
type CheckpointDigest struct {
	ffiObject FfiObject
}



func (object *CheckpointDigest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterCheckpointDigest struct {}

var FfiConverterCheckpointDigestINSTANCE = FfiConverterCheckpointDigest{}


func (c FfiConverterCheckpointDigest) Lift(pointer unsafe.Pointer) *CheckpointDigest {
	result := &CheckpointDigest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_checkpointdigest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_checkpointdigest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*CheckpointDigest).Destroy)
	return result
}

func (c FfiConverterCheckpointDigest) Read(reader io.Reader) *CheckpointDigest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterCheckpointDigest) Lower(value *CheckpointDigest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*CheckpointDigest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterCheckpointDigest) Write(writer io.Writer, value *CheckpointDigest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerCheckpointDigest struct {}

func (_ FfiDestroyerCheckpointDigest) Destroy(value *CheckpointDigest) {
		value.Destroy()
}



type CheckpointSummaryPageInterface interface {
	Data() []CheckpointSummary
	IsEmpty() bool
	PageInfo() *PageInfo
}
type CheckpointSummaryPage struct {
	ffiObject FfiObject
}




func (_self *CheckpointSummaryPage) Data() []CheckpointSummary {
	_pointer := _self.ffiObject.incrementPointer("*CheckpointSummaryPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceCheckpointSummaryINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_checkpointsummarypage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *CheckpointSummaryPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*CheckpointSummaryPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_checkpointsummarypage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *CheckpointSummaryPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*CheckpointSummaryPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_checkpointsummarypage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *CheckpointSummaryPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterCheckpointSummaryPage struct {}

var FfiConverterCheckpointSummaryPageINSTANCE = FfiConverterCheckpointSummaryPage{}


func (c FfiConverterCheckpointSummaryPage) Lift(pointer unsafe.Pointer) *CheckpointSummaryPage {
	result := &CheckpointSummaryPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_checkpointsummarypage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_checkpointsummarypage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*CheckpointSummaryPage).Destroy)
	return result
}

func (c FfiConverterCheckpointSummaryPage) Read(reader io.Reader) *CheckpointSummaryPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterCheckpointSummaryPage) Lower(value *CheckpointSummaryPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*CheckpointSummaryPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterCheckpointSummaryPage) Write(writer io.Writer, value *CheckpointSummaryPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerCheckpointSummaryPage struct {}

func (_ FfiDestroyerCheckpointSummaryPage) Destroy(value *CheckpointSummaryPage) {
		value.Destroy()
}



type CoinInterface interface {
	Balance() uint64
	CoinType() *TypeTag
	Id() *ObjectId
}
type Coin struct {
	ffiObject FfiObject
}


func CoinTryFromObject(object *Object) (*Coin, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_coin_try_from_object(FfiConverterObjectINSTANCE.Lower(object),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Coin
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterCoinINSTANCE.Lift(_uniffiRV), nil
		}
}



func (_self *Coin) Balance() uint64 {
	_pointer := _self.ffiObject.incrementPointer("*Coin")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterUint64INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_iota_sdk_ffi_fn_method_coin_balance(
		_pointer,_uniffiStatus)
	}))
}

func (_self *Coin) CoinType() *TypeTag {
	_pointer := _self.ffiObject.incrementPointer("*Coin")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterTypeTagINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_coin_coin_type(
		_pointer,_uniffiStatus)
	}))
}

func (_self *Coin) Id() *ObjectId {
	_pointer := _self.ffiObject.incrementPointer("*Coin")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterObjectIdINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_coin_id(
		_pointer,_uniffiStatus)
	}))
}
func (object *Coin) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterCoin struct {}

var FfiConverterCoinINSTANCE = FfiConverterCoin{}


func (c FfiConverterCoin) Lift(pointer unsafe.Pointer) *Coin {
	result := &Coin {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_coin(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_coin(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Coin).Destroy)
	return result
}

func (c FfiConverterCoin) Read(reader io.Reader) *Coin {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterCoin) Lower(value *Coin) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Coin")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterCoin) Write(writer io.Writer, value *Coin) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerCoin struct {}

func (_ FfiDestroyerCoin) Destroy(value *Coin) {
		value.Destroy()
}



type CoinMetadataInterface interface {
}
type CoinMetadata struct {
	ffiObject FfiObject
}



func (object *CoinMetadata) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterCoinMetadata struct {}

var FfiConverterCoinMetadataINSTANCE = FfiConverterCoinMetadata{}


func (c FfiConverterCoinMetadata) Lift(pointer unsafe.Pointer) *CoinMetadata {
	result := &CoinMetadata {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_coinmetadata(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_coinmetadata(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*CoinMetadata).Destroy)
	return result
}

func (c FfiConverterCoinMetadata) Read(reader io.Reader) *CoinMetadata {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterCoinMetadata) Lower(value *CoinMetadata) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*CoinMetadata")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterCoinMetadata) Write(writer io.Writer, value *CoinMetadata) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerCoinMetadata struct {}

func (_ FfiDestroyerCoinMetadata) Destroy(value *CoinMetadata) {
		value.Destroy()
}



type CoinPageInterface interface {
	Data() []*Coin
	IsEmpty() bool
	PageInfo() *PageInfo
}
type CoinPage struct {
	ffiObject FfiObject
}




func (_self *CoinPage) Data() []*Coin {
	_pointer := _self.ffiObject.incrementPointer("*CoinPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceCoinINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_coinpage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *CoinPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*CoinPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_coinpage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *CoinPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*CoinPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_coinpage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *CoinPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterCoinPage struct {}

var FfiConverterCoinPageINSTANCE = FfiConverterCoinPage{}


func (c FfiConverterCoinPage) Lift(pointer unsafe.Pointer) *CoinPage {
	result := &CoinPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_coinpage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_coinpage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*CoinPage).Destroy)
	return result
}

func (c FfiConverterCoinPage) Read(reader io.Reader) *CoinPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterCoinPage) Lower(value *CoinPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*CoinPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterCoinPage) Write(writer io.Writer, value *CoinPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerCoinPage struct {}

func (_ FfiDestroyerCoinPage) Destroy(value *CoinPage) {
		value.Destroy()
}



type ConsensusCommitDigestInterface interface {
}
type ConsensusCommitDigest struct {
	ffiObject FfiObject
}



func (object *ConsensusCommitDigest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterConsensusCommitDigest struct {}

var FfiConverterConsensusCommitDigestINSTANCE = FfiConverterConsensusCommitDigest{}


func (c FfiConverterConsensusCommitDigest) Lift(pointer unsafe.Pointer) *ConsensusCommitDigest {
	result := &ConsensusCommitDigest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_consensuscommitdigest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_consensuscommitdigest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ConsensusCommitDigest).Destroy)
	return result
}

func (c FfiConverterConsensusCommitDigest) Read(reader io.Reader) *ConsensusCommitDigest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterConsensusCommitDigest) Lower(value *ConsensusCommitDigest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ConsensusCommitDigest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterConsensusCommitDigest) Write(writer io.Writer, value *ConsensusCommitDigest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerConsensusCommitDigest struct {}

func (_ FfiDestroyerConsensusCommitDigest) Destroy(value *ConsensusCommitDigest) {
		value.Destroy()
}



type ConsensusCommitPrologueV1Interface interface {
}
type ConsensusCommitPrologueV1 struct {
	ffiObject FfiObject
}



func (object *ConsensusCommitPrologueV1) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterConsensusCommitPrologueV1 struct {}

var FfiConverterConsensusCommitPrologueV1INSTANCE = FfiConverterConsensusCommitPrologueV1{}


func (c FfiConverterConsensusCommitPrologueV1) Lift(pointer unsafe.Pointer) *ConsensusCommitPrologueV1 {
	result := &ConsensusCommitPrologueV1 {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_consensuscommitprologuev1(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_consensuscommitprologuev1(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ConsensusCommitPrologueV1).Destroy)
	return result
}

func (c FfiConverterConsensusCommitPrologueV1) Read(reader io.Reader) *ConsensusCommitPrologueV1 {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterConsensusCommitPrologueV1) Lower(value *ConsensusCommitPrologueV1) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ConsensusCommitPrologueV1")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterConsensusCommitPrologueV1) Write(writer io.Writer, value *ConsensusCommitPrologueV1) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerConsensusCommitPrologueV1 struct {}

func (_ FfiDestroyerConsensusCommitPrologueV1) Destroy(value *ConsensusCommitPrologueV1) {
		value.Destroy()
}



// A 32-byte Blake2b256 hash output.
//
// # BCS
//
// A `Digest`'s BCS serialized form is defined by the following:
//
// ```text
// digest = %x20 32OCTET
// ```
//
// Due to historical reasons, even though a `Digest` has a fixed-length of 32,
// IOTA's binary representation of a `Digest` is prefixed with its length
// meaning its serialized binary form (in bcs) is 33 bytes long vs a more
// compact 32 bytes.
type DigestInterface interface {
}
// A 32-byte Blake2b256 hash output.
//
// # BCS
//
// A `Digest`'s BCS serialized form is defined by the following:
//
// ```text
// digest = %x20 32OCTET
// ```
//
// Due to historical reasons, even though a `Digest` has a fixed-length of 32,
// IOTA's binary representation of a `Digest` is prefixed with its length
// meaning its serialized binary form (in bcs) is 33 bytes long vs a more
// compact 32 bytes.
type Digest struct {
	ffiObject FfiObject
}



func (object *Digest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterDigest struct {}

var FfiConverterDigestINSTANCE = FfiConverterDigest{}


func (c FfiConverterDigest) Lift(pointer unsafe.Pointer) *Digest {
	result := &Digest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_digest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_digest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Digest).Destroy)
	return result
}

func (c FfiConverterDigest) Read(reader io.Reader) *Digest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterDigest) Lower(value *Digest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Digest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterDigest) Write(writer io.Writer, value *Digest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerDigest struct {}

func (_ FfiDestroyerDigest) Destroy(value *Digest) {
		value.Destroy()
}



type DryRunResultInterface interface {
}
type DryRunResult struct {
	ffiObject FfiObject
}



func (object *DryRunResult) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterDryRunResult struct {}

var FfiConverterDryRunResultINSTANCE = FfiConverterDryRunResult{}


func (c FfiConverterDryRunResult) Lift(pointer unsafe.Pointer) *DryRunResult {
	result := &DryRunResult {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_dryrunresult(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_dryrunresult(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*DryRunResult).Destroy)
	return result
}

func (c FfiConverterDryRunResult) Read(reader io.Reader) *DryRunResult {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterDryRunResult) Lower(value *DryRunResult) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*DryRunResult")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterDryRunResult) Write(writer io.Writer, value *DryRunResult) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerDryRunResult struct {}

func (_ FfiDestroyerDryRunResult) Destroy(value *DryRunResult) {
		value.Destroy()
}



type DynamicFieldOutputInterface interface {
}
type DynamicFieldOutput struct {
	ffiObject FfiObject
}



func (object *DynamicFieldOutput) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterDynamicFieldOutput struct {}

var FfiConverterDynamicFieldOutputINSTANCE = FfiConverterDynamicFieldOutput{}


func (c FfiConverterDynamicFieldOutput) Lift(pointer unsafe.Pointer) *DynamicFieldOutput {
	result := &DynamicFieldOutput {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_dynamicfieldoutput(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_dynamicfieldoutput(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*DynamicFieldOutput).Destroy)
	return result
}

func (c FfiConverterDynamicFieldOutput) Read(reader io.Reader) *DynamicFieldOutput {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterDynamicFieldOutput) Lower(value *DynamicFieldOutput) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*DynamicFieldOutput")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterDynamicFieldOutput) Write(writer io.Writer, value *DynamicFieldOutput) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerDynamicFieldOutput struct {}

func (_ FfiDestroyerDynamicFieldOutput) Destroy(value *DynamicFieldOutput) {
		value.Destroy()
}



type DynamicFieldOutputPageInterface interface {
	Data() []*DynamicFieldOutput
	IsEmpty() bool
	PageInfo() *PageInfo
}
type DynamicFieldOutputPage struct {
	ffiObject FfiObject
}




func (_self *DynamicFieldOutputPage) Data() []*DynamicFieldOutput {
	_pointer := _self.ffiObject.incrementPointer("*DynamicFieldOutputPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceDynamicFieldOutputINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_dynamicfieldoutputpage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *DynamicFieldOutputPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*DynamicFieldOutputPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_dynamicfieldoutputpage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *DynamicFieldOutputPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*DynamicFieldOutputPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_dynamicfieldoutputpage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *DynamicFieldOutputPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterDynamicFieldOutputPage struct {}

var FfiConverterDynamicFieldOutputPageINSTANCE = FfiConverterDynamicFieldOutputPage{}


func (c FfiConverterDynamicFieldOutputPage) Lift(pointer unsafe.Pointer) *DynamicFieldOutputPage {
	result := &DynamicFieldOutputPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_dynamicfieldoutputpage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_dynamicfieldoutputpage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*DynamicFieldOutputPage).Destroy)
	return result
}

func (c FfiConverterDynamicFieldOutputPage) Read(reader io.Reader) *DynamicFieldOutputPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterDynamicFieldOutputPage) Lower(value *DynamicFieldOutputPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*DynamicFieldOutputPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterDynamicFieldOutputPage) Write(writer io.Writer, value *DynamicFieldOutputPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerDynamicFieldOutputPage struct {}

func (_ FfiDestroyerDynamicFieldOutputPage) Destroy(value *DynamicFieldOutputPage) {
		value.Destroy()
}



// An ed25519 public key.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// ed25519-public-key = 32OCTECT
// ```
type Ed25519PublicKeyInterface interface {
	ToBytes() []byte
}
// An ed25519 public key.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// ed25519-public-key = 32OCTECT
// ```
type Ed25519PublicKey struct {
	ffiObject FfiObject
}


func Ed25519PublicKeyFromBytes(bytes []byte) (*Ed25519PublicKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_ed25519publickey_from_bytes(FfiConverterBytesINSTANCE.Lower(bytes),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Ed25519PublicKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterEd25519PublicKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

func Ed25519PublicKeyFromStr(s string) (*Ed25519PublicKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_ed25519publickey_from_str(FfiConverterStringINSTANCE.Lower(s),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Ed25519PublicKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterEd25519PublicKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

func Ed25519PublicKeyGenerate() *Ed25519PublicKey {
	return FfiConverterEd25519PublicKeyINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_ed25519publickey_generate(_uniffiStatus)
	}))
}



func (_self *Ed25519PublicKey) ToBytes() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Ed25519PublicKey")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_ed25519publickey_to_bytes(
		_pointer,_uniffiStatus),
	}
	}))
}
func (object *Ed25519PublicKey) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterEd25519PublicKey struct {}

var FfiConverterEd25519PublicKeyINSTANCE = FfiConverterEd25519PublicKey{}


func (c FfiConverterEd25519PublicKey) Lift(pointer unsafe.Pointer) *Ed25519PublicKey {
	result := &Ed25519PublicKey {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_ed25519publickey(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_ed25519publickey(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Ed25519PublicKey).Destroy)
	return result
}

func (c FfiConverterEd25519PublicKey) Read(reader io.Reader) *Ed25519PublicKey {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterEd25519PublicKey) Lower(value *Ed25519PublicKey) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Ed25519PublicKey")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterEd25519PublicKey) Write(writer io.Writer, value *Ed25519PublicKey) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerEd25519PublicKey struct {}

func (_ FfiDestroyerEd25519PublicKey) Destroy(value *Ed25519PublicKey) {
		value.Destroy()
}



type EffectsAuxiliaryDataDigestInterface interface {
}
type EffectsAuxiliaryDataDigest struct {
	ffiObject FfiObject
}



func (object *EffectsAuxiliaryDataDigest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterEffectsAuxiliaryDataDigest struct {}

var FfiConverterEffectsAuxiliaryDataDigestINSTANCE = FfiConverterEffectsAuxiliaryDataDigest{}


func (c FfiConverterEffectsAuxiliaryDataDigest) Lift(pointer unsafe.Pointer) *EffectsAuxiliaryDataDigest {
	result := &EffectsAuxiliaryDataDigest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_effectsauxiliarydatadigest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_effectsauxiliarydatadigest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*EffectsAuxiliaryDataDigest).Destroy)
	return result
}

func (c FfiConverterEffectsAuxiliaryDataDigest) Read(reader io.Reader) *EffectsAuxiliaryDataDigest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterEffectsAuxiliaryDataDigest) Lower(value *EffectsAuxiliaryDataDigest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*EffectsAuxiliaryDataDigest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterEffectsAuxiliaryDataDigest) Write(writer io.Writer, value *EffectsAuxiliaryDataDigest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerEffectsAuxiliaryDataDigest struct {}

func (_ FfiDestroyerEffectsAuxiliaryDataDigest) Destroy(value *EffectsAuxiliaryDataDigest) {
		value.Destroy()
}



// Operation run at the end of an epoch
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// end-of-epoch-transaction-kind   =  eoe-change-epoch
// =/ eoe-authenticator-state-create
// =/ eoe-authenticator-state-expire
// =/ eoe-randomness-state-create
// =/ eoe-deny-list-state-create
// =/ eoe-bridge-state-create
// =/ eoe-bridge-committee-init
// =/ eoe-store-execution-time-observations
//
// eoe-change-epoch                = %x00 change-epoch
// eoe-authenticator-state-create  = %x01
// eoe-authenticator-state-expire  = %x02 authenticator-state-expire
// eoe-randomness-state-create     = %x03
// eoe-deny-list-state-create      = %x04
// eoe-bridge-state-create         = %x05 digest
// eoe-bridge-committee-init       = %x06 u64
// eoe-store-execution-time-observations = %x07 stored-execution-time-observations
// ```
type EndOfEpochTransactionKindInterface interface {
}
// Operation run at the end of an epoch
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// end-of-epoch-transaction-kind   =  eoe-change-epoch
// =/ eoe-authenticator-state-create
// =/ eoe-authenticator-state-expire
// =/ eoe-randomness-state-create
// =/ eoe-deny-list-state-create
// =/ eoe-bridge-state-create
// =/ eoe-bridge-committee-init
// =/ eoe-store-execution-time-observations
//
// eoe-change-epoch                = %x00 change-epoch
// eoe-authenticator-state-create  = %x01
// eoe-authenticator-state-expire  = %x02 authenticator-state-expire
// eoe-randomness-state-create     = %x03
// eoe-deny-list-state-create      = %x04
// eoe-bridge-state-create         = %x05 digest
// eoe-bridge-committee-init       = %x06 u64
// eoe-store-execution-time-observations = %x07 stored-execution-time-observations
// ```
type EndOfEpochTransactionKind struct {
	ffiObject FfiObject
}


func EndOfEpochTransactionKindAuthenticatorStateCreate() *EndOfEpochTransactionKind {
	return FfiConverterEndOfEpochTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_authenticator_state_create(_uniffiStatus)
	}))
}

func EndOfEpochTransactionKindAuthenticatorStateExpire(tx *AuthenticatorStateExpire) *EndOfEpochTransactionKind {
	return FfiConverterEndOfEpochTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_authenticator_state_expire(FfiConverterAuthenticatorStateExpireINSTANCE.Lower(tx),_uniffiStatus)
	}))
}

func EndOfEpochTransactionKindChangeEpoch(tx *ChangeEpoch) *EndOfEpochTransactionKind {
	return FfiConverterEndOfEpochTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_change_epoch(FfiConverterChangeEpochINSTANCE.Lower(tx),_uniffiStatus)
	}))
}

func EndOfEpochTransactionKindChangeEpochV2(tx *ChangeEpochV2) *EndOfEpochTransactionKind {
	return FfiConverterEndOfEpochTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_change_epoch_v2(FfiConverterChangeEpochV2INSTANCE.Lower(tx),_uniffiStatus)
	}))
}


func (object *EndOfEpochTransactionKind) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterEndOfEpochTransactionKind struct {}

var FfiConverterEndOfEpochTransactionKindINSTANCE = FfiConverterEndOfEpochTransactionKind{}


func (c FfiConverterEndOfEpochTransactionKind) Lift(pointer unsafe.Pointer) *EndOfEpochTransactionKind {
	result := &EndOfEpochTransactionKind {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_endofepochtransactionkind(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_endofepochtransactionkind(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*EndOfEpochTransactionKind).Destroy)
	return result
}

func (c FfiConverterEndOfEpochTransactionKind) Read(reader io.Reader) *EndOfEpochTransactionKind {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterEndOfEpochTransactionKind) Lower(value *EndOfEpochTransactionKind) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*EndOfEpochTransactionKind")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterEndOfEpochTransactionKind) Write(writer io.Writer, value *EndOfEpochTransactionKind) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerEndOfEpochTransactionKind struct {}

func (_ FfiDestroyerEndOfEpochTransactionKind) Destroy(value *EndOfEpochTransactionKind) {
		value.Destroy()
}



type EpochInterface interface {
}
type Epoch struct {
	ffiObject FfiObject
}



func (object *Epoch) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterEpoch struct {}

var FfiConverterEpochINSTANCE = FfiConverterEpoch{}


func (c FfiConverterEpoch) Lift(pointer unsafe.Pointer) *Epoch {
	result := &Epoch {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_epoch(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_epoch(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Epoch).Destroy)
	return result
}

func (c FfiConverterEpoch) Read(reader io.Reader) *Epoch {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterEpoch) Lower(value *Epoch) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Epoch")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterEpoch) Write(writer io.Writer, value *Epoch) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerEpoch struct {}

func (_ FfiDestroyerEpoch) Destroy(value *Epoch) {
		value.Destroy()
}



type EpochPageInterface interface {
	Data() []*Epoch
	IsEmpty() bool
	PageInfo() *PageInfo
}
type EpochPage struct {
	ffiObject FfiObject
}




func (_self *EpochPage) Data() []*Epoch {
	_pointer := _self.ffiObject.incrementPointer("*EpochPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceEpochINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_epochpage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *EpochPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*EpochPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_epochpage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *EpochPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*EpochPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_epochpage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *EpochPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterEpochPage struct {}

var FfiConverterEpochPageINSTANCE = FfiConverterEpochPage{}


func (c FfiConverterEpochPage) Lift(pointer unsafe.Pointer) *EpochPage {
	result := &EpochPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_epochpage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_epochpage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*EpochPage).Destroy)
	return result
}

func (c FfiConverterEpochPage) Read(reader io.Reader) *EpochPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterEpochPage) Lower(value *EpochPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*EpochPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterEpochPage) Write(writer io.Writer, value *EpochPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerEpochPage struct {}

func (_ FfiDestroyerEpochPage) Destroy(value *EpochPage) {
		value.Destroy()
}



type EventInterface interface {
}
type Event struct {
	ffiObject FfiObject
}



func (object *Event) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterEvent struct {}

var FfiConverterEventINSTANCE = FfiConverterEvent{}


func (c FfiConverterEvent) Lift(pointer unsafe.Pointer) *Event {
	result := &Event {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_event(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_event(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Event).Destroy)
	return result
}

func (c FfiConverterEvent) Read(reader io.Reader) *Event {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterEvent) Lower(value *Event) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Event")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterEvent) Write(writer io.Writer, value *Event) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerEvent struct {}

func (_ FfiDestroyerEvent) Destroy(value *Event) {
		value.Destroy()
}



type EventPageInterface interface {
	Data() []*Event
	IsEmpty() bool
	PageInfo() *PageInfo
}
type EventPage struct {
	ffiObject FfiObject
}




func (_self *EventPage) Data() []*Event {
	_pointer := _self.ffiObject.incrementPointer("*EventPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceEventINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_eventpage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *EventPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*EventPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_eventpage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *EventPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*EventPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_eventpage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *EventPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterEventPage struct {}

var FfiConverterEventPageINSTANCE = FfiConverterEventPage{}


func (c FfiConverterEventPage) Lift(pointer unsafe.Pointer) *EventPage {
	result := &EventPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_eventpage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_eventpage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*EventPage).Destroy)
	return result
}

func (c FfiConverterEventPage) Read(reader io.Reader) *EventPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterEventPage) Lower(value *EventPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*EventPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterEventPage) Write(writer io.Writer, value *EventPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerEventPage struct {}

func (_ FfiDestroyerEventPage) Destroy(value *EventPage) {
		value.Destroy()
}



type ExecutionTimeObservationsInterface interface {
}
type ExecutionTimeObservations struct {
	ffiObject FfiObject
}



func (object *ExecutionTimeObservations) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterExecutionTimeObservations struct {}

var FfiConverterExecutionTimeObservationsINSTANCE = FfiConverterExecutionTimeObservations{}


func (c FfiConverterExecutionTimeObservations) Lift(pointer unsafe.Pointer) *ExecutionTimeObservations {
	result := &ExecutionTimeObservations {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_executiontimeobservations(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_executiontimeobservations(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ExecutionTimeObservations).Destroy)
	return result
}

func (c FfiConverterExecutionTimeObservations) Read(reader io.Reader) *ExecutionTimeObservations {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterExecutionTimeObservations) Lower(value *ExecutionTimeObservations) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ExecutionTimeObservations")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterExecutionTimeObservations) Write(writer io.Writer, value *ExecutionTimeObservations) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerExecutionTimeObservations struct {}

func (_ FfiDestroyerExecutionTimeObservations) Destroy(value *ExecutionTimeObservations) {
		value.Destroy()
}



type FaucetClientInterface interface {
	// Request gas from the faucet. Note that this will return the UUID of the
	// request and not wait until the token is received. Use
	// `request_and_wait` to wait for the token.
	Request(address *Address) (*string, error)
	// Request gas from the faucet and wait until the request is completed and
	// token is transferred. Returns `FaucetReceipt` if the request is
	// successful, which contains the list of tokens transferred, and the
	// transaction digest.
	//
	// Note that the faucet is heavily rate-limited, so calling repeatedly the
	// faucet would likely result in a 429 code or 502 code.
	RequestAndWait(address *Address) (**FaucetReceipt, error)
	// Check the faucet request status.
	//
	// Possible statuses are defined in: [`BatchSendStatusType`]
	RequestStatus(id string) (**BatchSendStatus, error)
}
type FaucetClient struct {
	ffiObject FfiObject
}
// Construct a new `FaucetClient` with the given faucet service URL. This
// [`FaucetClient`] expects that the service provides two endpoints:
// /v1/gas and /v1/status. As such, do not provide the request
// endpoint, just the top level service endpoint.
//
// - /v1/gas is used to request gas
// - /v1/status/taks-uuid is used to check the status of the request
func NewFaucetClient(faucetUrl string) *FaucetClient {
	return FfiConverterFaucetClientINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_faucetclient_new(FfiConverterStringINSTANCE.Lower(faucetUrl),_uniffiStatus)
	}))
}


// Set to devnet faucet.
func FaucetClientDevnet() *FaucetClient {
	return FfiConverterFaucetClientINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_faucetclient_devnet(_uniffiStatus)
	}))
}

// Set to local faucet.
func FaucetClientLocal() *FaucetClient {
	return FfiConverterFaucetClientINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_faucetclient_local(_uniffiStatus)
	}))
}

// Set to testnet faucet.
func FaucetClientTestnet() *FaucetClient {
	return FfiConverterFaucetClientINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_faucetclient_testnet(_uniffiStatus)
	}))
}



// Request gas from the faucet. Note that this will return the UUID of the
// request and not wait until the token is received. Use
// `request_and_wait` to wait for the token.
func (_self *FaucetClient) Request(address *Address) (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*FaucetClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *string {
			return FfiConverterOptionalStringINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_faucetclient_request(
		_pointer,FfiConverterAddressINSTANCE.Lower(address)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Request gas from the faucet and wait until the request is completed and
// token is transferred. Returns `FaucetReceipt` if the request is
// successful, which contains the list of tokens transferred, and the
// transaction digest.
//
// Note that the faucet is heavily rate-limited, so calling repeatedly the
// faucet would likely result in a 429 code or 502 code.
func (_self *FaucetClient) RequestAndWait(address *Address) (**FaucetReceipt, error) {
	_pointer := _self.ffiObject.incrementPointer("*FaucetClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **FaucetReceipt {
			return FfiConverterOptionalFaucetReceiptINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_faucetclient_request_and_wait(
		_pointer,FfiConverterAddressINSTANCE.Lower(address)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Check the faucet request status.
//
// Possible statuses are defined in: [`BatchSendStatusType`]
func (_self *FaucetClient) RequestStatus(id string) (**BatchSendStatus, error) {
	_pointer := _self.ffiObject.incrementPointer("*FaucetClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **BatchSendStatus {
			return FfiConverterOptionalBatchSendStatusINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_faucetclient_request_status(
		_pointer,FfiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}
func (object *FaucetClient) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterFaucetClient struct {}

var FfiConverterFaucetClientINSTANCE = FfiConverterFaucetClient{}


func (c FfiConverterFaucetClient) Lift(pointer unsafe.Pointer) *FaucetClient {
	result := &FaucetClient {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_faucetclient(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_faucetclient(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*FaucetClient).Destroy)
	return result
}

func (c FfiConverterFaucetClient) Read(reader io.Reader) *FaucetClient {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterFaucetClient) Lower(value *FaucetClient) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*FaucetClient")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterFaucetClient) Write(writer io.Writer, value *FaucetClient) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerFaucetClient struct {}

func (_ FfiDestroyerFaucetClient) Destroy(value *FaucetClient) {
		value.Destroy()
}



type FaucetReceiptInterface interface {
}
type FaucetReceipt struct {
	ffiObject FfiObject
}



func (object *FaucetReceipt) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterFaucetReceipt struct {}

var FfiConverterFaucetReceiptINSTANCE = FfiConverterFaucetReceipt{}


func (c FfiConverterFaucetReceipt) Lift(pointer unsafe.Pointer) *FaucetReceipt {
	result := &FaucetReceipt {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_faucetreceipt(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_faucetreceipt(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*FaucetReceipt).Destroy)
	return result
}

func (c FfiConverterFaucetReceipt) Read(reader io.Reader) *FaucetReceipt {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterFaucetReceipt) Lower(value *FaucetReceipt) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*FaucetReceipt")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterFaucetReceipt) Write(writer io.Writer, value *FaucetReceipt) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerFaucetReceipt struct {}

func (_ FfiDestroyerFaucetReceipt) Destroy(value *FaucetReceipt) {
		value.Destroy()
}



type GenesisTransactionInterface interface {
}
type GenesisTransaction struct {
	ffiObject FfiObject
}



func (object *GenesisTransaction) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterGenesisTransaction struct {}

var FfiConverterGenesisTransactionINSTANCE = FfiConverterGenesisTransaction{}


func (c FfiConverterGenesisTransaction) Lift(pointer unsafe.Pointer) *GenesisTransaction {
	result := &GenesisTransaction {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_genesistransaction(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_genesistransaction(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*GenesisTransaction).Destroy)
	return result
}

func (c FfiConverterGenesisTransaction) Read(reader io.Reader) *GenesisTransaction {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterGenesisTransaction) Lower(value *GenesisTransaction) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*GenesisTransaction")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterGenesisTransaction) Write(writer io.Writer, value *GenesisTransaction) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerGenesisTransaction struct {}

func (_ FfiDestroyerGenesisTransaction) Destroy(value *GenesisTransaction) {
		value.Destroy()
}



type GraphQlClientInterface interface {
	// Get the list of active validators for the provided epoch, including
	// related metadata. If no epoch is provided, it will return the active
	// validators for the current epoch.
	ActiveValidators(paginationFilter PaginationFilter, epoch *uint64) (*ValidatorPage, error)
	// Get the balance of all the coins owned by address for the provided coin
	// type. Coin type will default to `0x2::coin::Coin<0x2::iota::IOTA>`
	// if not provided.
	Balance(address *Address, coinType *string) (*uint64, error)
	// Get the chain identifier.
	ChainId() (string, error)
	// Get the [`CheckpointSummary`] for a given checkpoint digest or
	// checkpoint id. If none is provided, it will use the last known
	// checkpoint id.
	Checkpoint(digest **CheckpointContentsDigest, seqNum *uint64) (*CheckpointSummary, error)
	// Get a page of [`CheckpointSummary`] for the provided parameters.
	Checkpoints(paginationFilter PaginationFilter) (*CheckpointSummaryPage, error)
	// Get the coin metadata for the coin type.
	CoinMetadata(coinType string) (**CoinMetadata, error)
	// Get the list of coins for the specified address.
	//
	// If `coin_type` is not provided, it will default to `0x2::coin::Coin`,
	// which will return all coins. For IOTA coin, pass in the coin type:
	// `0x2::coin::Coin<0x2::iota::IOTA>`.
	Coins(owner *Address, paginationFilter PaginationFilter, coinType *string) (*CoinPage, error)
	// Dry run a [`Transaction`] and return the transaction effects and dry run
	// error (if any).
	//
	// `skipChecks` optional flag disables the usual verification checks that
	// prevent access to objects that are owned by addresses other than the
	// sender, and calling non-public, non-entry functions, and some other
	// checks. Defaults to false.
	DryRunTx(tx *Transaction, skipChecks *bool) (*DryRunResult, error)
	// Dry run a [`TransactionKind`] and return the transaction effects and dry
	// run error (if any).
	//
	// `skipChecks` optional flag disables the usual verification checks that
	// prevent access to objects that are owned by addresses other than the
	// sender, and calling non-public, non-entry functions, and some other
	// checks. Defaults to false.
	//
	// `tx_meta` is the transaction metadata.
	DryRunTxKind(txKind *TransactionKind, txMeta TransactionMetadata, skipChecks *bool) (*DryRunResult, error)
	// Access a dynamic field on an object using its name. Names are arbitrary
	// Move values whose type have copy, drop, and store, and are specified
	// using their type, and their BCS contents, Base64 encoded.
	//
	// The `name` argument is a json serialized type.
	//
	// This returns [`DynamicFieldOutput`] which contains the name, the value
	// as json, and object.
	//
	// # Example
	// ```rust,ignore
	//
	// let client = iota_graphql_client::Client::new_devnet();
	// let address = Address::from_str("0x5").unwrap();
	// let df = client.dynamic_field_with_name(address, "u64", 2u64).await.unwrap();
	//
	// # alternatively, pass in the bcs bytes
	// let bcs = base64ct::Base64::decode_vec("AgAAAAAAAAA=").unwrap();
	// let df = client.dynamic_field(address, "u64", BcsName(bcs)).await.unwrap();
	// ```
	DynamicField(address *Address, typeTag *TypeTag, name Value) (**DynamicFieldOutput, error)
	// Get a page of dynamic fields for the provided address. Note that this
	// will also fetch dynamic fields on wrapped objects.
	//
	// This returns [`Page`] of [`DynamicFieldOutput`]s.
	DynamicFields(address *Address, paginationFilter PaginationFilter) (*DynamicFieldOutputPage, error)
	// Access a dynamic object field on an object using its name. Names are
	// arbitrary Move values whose type have copy, drop, and store, and are
	// specified using their type, and their BCS contents, Base64 encoded.
	//
	// The `name` argument is a json serialized type.
	//
	// This returns [`DynamicFieldOutput`] which contains the name, the value
	// as json, and object.
	DynamicObjectField(address *Address, typeTag *TypeTag, name Value) (**DynamicFieldOutput, error)
	// Return the epoch information for the provided epoch. If no epoch is
	// provided, it will return the last known epoch.
	Epoch(epoch *uint64) (**Epoch, error)
	// Return the number of checkpoints in this epoch. This will return
	// `Ok(None)` if the epoch requested is not available in the GraphQL
	// service (e.g., due to pruning).
	EpochTotalCheckpoints(epoch *uint64) (*uint64, error)
	// Return the number of transaction blocks in this epoch. This will return
	// `Ok(None)` if the epoch requested is not available in the GraphQL
	// service (e.g., due to pruning).
	EpochTotalTransactionBlocks(epoch *uint64) (*uint64, error)
	// Return a page of tuple (event, transaction digest) based on the
	// (optional) event filter.
	Events(paginationFilter PaginationFilter, filter *EventFilter) (*EventPage, error)
	// Execute a transaction.
	ExecuteTx(signatures []*UserSignature, tx *Transaction) (**TransactionEffects, error)
	// Return the sequence number of the latest checkpoint that has been
	// executed.
	LatestCheckpointSequenceNumber() (*uint64, error)
	// Lazily fetch the max page size
	MaxPageSize() (int32, error)
	// Return the contents' JSON of an object that is a Move object.
	//
	// If the object does not exist (e.g., due to pruning), this will return
	// `Ok(None)`. Similarly, if this is not an object but an address, it
	// will return `Ok(None)`.
	MoveObjectContents(objectId *ObjectId, version *uint64) (*Value, error)
	// Return the BCS of an object that is a Move object.
	//
	// If the object does not exist (e.g., due to pruning), this will return
	// `Ok(None)`. Similarly, if this is not an object but an address, it
	// will return `Ok(None)`.
	MoveObjectContentsBcs(objectId *ObjectId, version *uint64) (*[]byte, error)
	// Return the normalized Move function data for the provided package,
	// module, and function.
	NormalizedMoveFunction(varPackage string, module string, function string, version *uint64) (**MoveFunction, error)
	// Return the normalized Move module data for the provided module.
	NormalizedMoveModule(varPackage string, module string, paginationFilterEnums PaginationFilter, paginationFilterFriends PaginationFilter, paginationFilterFunctions PaginationFilter, paginationFilterStructs PaginationFilter, version *uint64) (**MoveModule, error)
	// Return an object based on the provided [`Address`].
	//
	// If the object does not exist (e.g., due to pruning), this will return
	// `Ok(None)`. Similarly, if this is not an object but an address, it
	// will return `Ok(None)`.
	Object(objectId *ObjectId, version *uint64) (**Object, error)
	// Return the object's bcs content [`Vec<u8>`] based on the provided
	// [`Address`].
	ObjectBcs(objectId *ObjectId) (*[]byte, error)
	// Return a page of objects based on the provided parameters.
	//
	// Use this function together with the [`ObjectFilter::owner`] to get the
	// objects owned by an address.
	//
	// # Example
	//
	// ```rust,ignore
	// let filter = ObjectFilter {
	// type_: None,
	// owner: Some(Address::from_str("test").unwrap().into()),
	// object_ids: None,
	// };
	//
	// let owned_objects = client.objects(None, None, Some(filter), None, None).await;
	// ```
	Objects(paginationFilter PaginationFilter, filter **ObjectFilter) (*ObjectPage, error)
	// The package corresponding to the given address (at the optionally given
	// version). When no version is given, the package is loaded directly
	// from the address given. Otherwise, the address is translated before
	// loading to point to the package whose original ID matches
	// the package at address, but whose version is version. For non-system
	// packages, this might result in a different address than address
	// because different versions of a package, introduced by upgrades,
	// exist at distinct addresses.
	//
	// Note that this interpretation of version is different from a historical
	// object read (the interpretation of version for the object query).
	Package(address *Address, version *uint64) (**MovePackage, error)
	// Fetch the latest version of the package at address.
	// This corresponds to the package with the highest version that shares its
	// original ID with the package at address.
	PackageLatest(address *Address) (**MovePackage, error)
	// Fetch all versions of package at address (packages that share this
	// package's original ID), optionally bounding the versions exclusively
	// from below with afterVersion, or from above with beforeVersion.
	PackageVersions(address *Address, paginationFilter PaginationFilter, afterVersion *uint64, beforeVersion *uint64) (*MovePackagePage, error)
	// The Move packages that exist in the network, optionally filtered to be
	// strictly before beforeCheckpoint and/or strictly after
	// afterCheckpoint.
	//
	// This query returns all versions of a given user package that appear
	// between the specified checkpoints, but only records the latest
	// versions of system packages.
	Packages(paginationFilter PaginationFilter, afterCheckpoint *uint64, beforeCheckpoint *uint64) (*MovePackagePage, error)
	// Get the protocol configuration.
	ProtocolConfig(version *uint64) (**ProtocolConfigs, error)
	// Get the reference gas price for the provided epoch or the last known one
	// if no epoch is provided.
	//
	// This will return `Ok(None)` if the epoch requested is not available in
	// the GraphQL service (e.g., due to pruning).
	ReferenceGasPrice(epoch *uint64) (*uint64, error)
	// Get the GraphQL service configuration, including complexity limits, read
	// and mutation limits, supported versions, and others.
	ServiceConfig() (*ServiceConfig, error)
	// Set the server address for the GraphQL GraphQL client. It should be a
	// valid URL with a host and optionally a port number.
	SetRpcServer(server string) error
	// Get total supply for the coin type.
	TotalSupply(coinType string) (*uint64, error)
	// The total number of transaction blocks in the network by the end of the
	// last known checkpoint.
	TotalTransactionBlocks() (*uint64, error)
	// The total number of transaction blocks in the network by the end of the
	// provided checkpoint digest.
	TotalTransactionBlocksByDigest(digest *CheckpointContentsDigest) (*uint64, error)
	// The total number of transaction blocks in the network by the end of the
	// provided checkpoint sequence number.
	TotalTransactionBlocksBySeqNum(seqNum uint64) (*uint64, error)
	// Get a transaction by its digest.
	Transaction(digest *TransactionDigest) (**SignedTransaction, error)
	// Get a transaction's data and effects by its digest.
	TransactionDataEffects(digest *TransactionDigest) (**TransactionDataEffects, error)
	// Get a transaction's effects by its digest.
	TransactionEffects(digest *TransactionDigest) (**TransactionEffects, error)
	// Get a page of transactions based on the provided filters.
	Transactions(paginationFilter PaginationFilter, filter *TransactionsFilter) (*SignedTransactionPage, error)
	// Get a page of transactions' data and effects based on the provided
	// filters.
	TransactionsDataEffects(paginationFilter PaginationFilter, filter *TransactionsFilter) (*TransactionDataEffectsPage, error)
	// Get a page of transactions' effects based on the provided filters.
	TransactionsEffects(paginationFilter PaginationFilter, filter *TransactionsFilter) (*TransactionEffectsPage, error)
}
type GraphQlClient struct {
	ffiObject FfiObject
}
// Create a new GraphQL client with the provided server address.
func NewGraphQlClient(server string) (*GraphQlClient, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new(FfiConverterStringINSTANCE.Lower(server),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *GraphQlClient
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterGraphQlClientINSTANCE.Lift(_uniffiRV), nil
		}
}


// Create a new GraphQL client connected to the `devnet` GraphQL server:
// {DEVNET_HOST}.
func GraphQlClientNewDevnet() *GraphQlClient {
	return FfiConverterGraphQlClientINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new_devnet(_uniffiStatus)
	}))
}

// Create a new GraphQL client connected to the `localhost` GraphQL server:
// {DEFAULT_LOCAL_HOST}.
func GraphQlClientNewLocalhost() *GraphQlClient {
	return FfiConverterGraphQlClientINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new_localhost(_uniffiStatus)
	}))
}

// Create a new GraphQL client connected to the `mainnet` GraphQL server:
// {MAINNET_HOST}.
func GraphQlClientNewMainnet() *GraphQlClient {
	return FfiConverterGraphQlClientINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new_mainnet(_uniffiStatus)
	}))
}

// Create a new GraphQL client connected to the `testnet` GraphQL server:
// {TESTNET_HOST}.
func GraphQlClientNewTestnet() *GraphQlClient {
	return FfiConverterGraphQlClientINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new_testnet(_uniffiStatus)
	}))
}



// Get the list of active validators for the provided epoch, including
// related metadata. If no epoch is provided, it will return the active
// validators for the current epoch.
func (_self *GraphQlClient) ActiveValidators(paginationFilter PaginationFilter, epoch *uint64) (*ValidatorPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *ValidatorPage {
			return FfiConverterValidatorPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_active_validators(
		_pointer,FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalUint64INSTANCE.Lower(epoch)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Get the balance of all the coins owned by address for the provided coin
// type. Coin type will default to `0x2::coin::Coin<0x2::iota::IOTA>`
// if not provided.
func (_self *GraphQlClient) Balance(address *Address, coinType *string) (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_balance(
		_pointer,FfiConverterAddressINSTANCE.Lower(address), FfiConverterOptionalStringINSTANCE.Lower(coinType)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get the chain identifier.
func (_self *GraphQlClient) ChainId() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_chain_id(
		_pointer,),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get the [`CheckpointSummary`] for a given checkpoint digest or
// checkpoint id. If none is provided, it will use the last known
// checkpoint id.
func (_self *GraphQlClient) Checkpoint(digest **CheckpointContentsDigest, seqNum *uint64) (*CheckpointSummary, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *CheckpointSummary {
			return FfiConverterOptionalCheckpointSummaryINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_checkpoint(
		_pointer,FfiConverterOptionalCheckpointContentsDigestINSTANCE.Lower(digest), FfiConverterOptionalUint64INSTANCE.Lower(seqNum)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get a page of [`CheckpointSummary`] for the provided parameters.
func (_self *GraphQlClient) Checkpoints(paginationFilter PaginationFilter) (*CheckpointSummaryPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *CheckpointSummaryPage {
			return FfiConverterCheckpointSummaryPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_checkpoints(
		_pointer,FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Get the coin metadata for the coin type.
func (_self *GraphQlClient) CoinMetadata(coinType string) (**CoinMetadata, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **CoinMetadata {
			return FfiConverterOptionalCoinMetadataINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_coin_metadata(
		_pointer,FfiConverterStringINSTANCE.Lower(coinType)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get the list of coins for the specified address.
//
// If `coin_type` is not provided, it will default to `0x2::coin::Coin`,
// which will return all coins. For IOTA coin, pass in the coin type:
// `0x2::coin::Coin<0x2::iota::IOTA>`.
func (_self *GraphQlClient) Coins(owner *Address, paginationFilter PaginationFilter, coinType *string) (*CoinPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *CoinPage {
			return FfiConverterCoinPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_coins(
		_pointer,FfiConverterAddressINSTANCE.Lower(owner), FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalStringINSTANCE.Lower(coinType)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Dry run a [`Transaction`] and return the transaction effects and dry run
// error (if any).
//
// `skipChecks` optional flag disables the usual verification checks that
// prevent access to objects that are owned by addresses other than the
// sender, and calling non-public, non-entry functions, and some other
// checks. Defaults to false.
func (_self *GraphQlClient) DryRunTx(tx *Transaction, skipChecks *bool) (*DryRunResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *DryRunResult {
			return FfiConverterDryRunResultINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_dry_run_tx(
		_pointer,FfiConverterTransactionINSTANCE.Lower(tx), FfiConverterOptionalBoolINSTANCE.Lower(skipChecks)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Dry run a [`TransactionKind`] and return the transaction effects and dry
// run error (if any).
//
// `skipChecks` optional flag disables the usual verification checks that
// prevent access to objects that are owned by addresses other than the
// sender, and calling non-public, non-entry functions, and some other
// checks. Defaults to false.
//
// `tx_meta` is the transaction metadata.
func (_self *GraphQlClient) DryRunTxKind(txKind *TransactionKind, txMeta TransactionMetadata, skipChecks *bool) (*DryRunResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *DryRunResult {
			return FfiConverterDryRunResultINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_dry_run_tx_kind(
		_pointer,FfiConverterTransactionKindINSTANCE.Lower(txKind), FfiConverterTransactionMetadataINSTANCE.Lower(txMeta), FfiConverterOptionalBoolINSTANCE.Lower(skipChecks)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Access a dynamic field on an object using its name. Names are arbitrary
// Move values whose type have copy, drop, and store, and are specified
// using their type, and their BCS contents, Base64 encoded.
//
// The `name` argument is a json serialized type.
//
// This returns [`DynamicFieldOutput`] which contains the name, the value
// as json, and object.
//
// # Example
// ```rust,ignore
//
// let client = iota_graphql_client::Client::new_devnet();
// let address = Address::from_str("0x5").unwrap();
// let df = client.dynamic_field_with_name(address, "u64", 2u64).await.unwrap();
//
// # alternatively, pass in the bcs bytes
// let bcs = base64ct::Base64::decode_vec("AgAAAAAAAAA=").unwrap();
// let df = client.dynamic_field(address, "u64", BcsName(bcs)).await.unwrap();
// ```
func (_self *GraphQlClient) DynamicField(address *Address, typeTag *TypeTag, name Value) (**DynamicFieldOutput, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **DynamicFieldOutput {
			return FfiConverterOptionalDynamicFieldOutputINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_dynamic_field(
		_pointer,FfiConverterAddressINSTANCE.Lower(address), FfiConverterTypeTagINSTANCE.Lower(typeTag), FfiConverterTypeValueINSTANCE.Lower(name)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get a page of dynamic fields for the provided address. Note that this
// will also fetch dynamic fields on wrapped objects.
//
// This returns [`Page`] of [`DynamicFieldOutput`]s.
func (_self *GraphQlClient) DynamicFields(address *Address, paginationFilter PaginationFilter) (*DynamicFieldOutputPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *DynamicFieldOutputPage {
			return FfiConverterDynamicFieldOutputPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_dynamic_fields(
		_pointer,FfiConverterAddressINSTANCE.Lower(address), FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Access a dynamic object field on an object using its name. Names are
// arbitrary Move values whose type have copy, drop, and store, and are
// specified using their type, and their BCS contents, Base64 encoded.
//
// The `name` argument is a json serialized type.
//
// This returns [`DynamicFieldOutput`] which contains the name, the value
// as json, and object.
func (_self *GraphQlClient) DynamicObjectField(address *Address, typeTag *TypeTag, name Value) (**DynamicFieldOutput, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **DynamicFieldOutput {
			return FfiConverterOptionalDynamicFieldOutputINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_dynamic_object_field(
		_pointer,FfiConverterAddressINSTANCE.Lower(address), FfiConverterTypeTagINSTANCE.Lower(typeTag), FfiConverterTypeValueINSTANCE.Lower(name)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return the epoch information for the provided epoch. If no epoch is
// provided, it will return the last known epoch.
func (_self *GraphQlClient) Epoch(epoch *uint64) (**Epoch, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **Epoch {
			return FfiConverterOptionalEpochINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_epoch(
		_pointer,FfiConverterOptionalUint64INSTANCE.Lower(epoch)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return the number of checkpoints in this epoch. This will return
// `Ok(None)` if the epoch requested is not available in the GraphQL
// service (e.g., due to pruning).
func (_self *GraphQlClient) EpochTotalCheckpoints(epoch *uint64) (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_epoch_total_checkpoints(
		_pointer,FfiConverterOptionalUint64INSTANCE.Lower(epoch)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return the number of transaction blocks in this epoch. This will return
// `Ok(None)` if the epoch requested is not available in the GraphQL
// service (e.g., due to pruning).
func (_self *GraphQlClient) EpochTotalTransactionBlocks(epoch *uint64) (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_epoch_total_transaction_blocks(
		_pointer,FfiConverterOptionalUint64INSTANCE.Lower(epoch)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return a page of tuple (event, transaction digest) based on the
// (optional) event filter.
func (_self *GraphQlClient) Events(paginationFilter PaginationFilter, filter *EventFilter) (*EventPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *EventPage {
			return FfiConverterEventPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_events(
		_pointer,FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalEventFilterINSTANCE.Lower(filter)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Execute a transaction.
func (_self *GraphQlClient) ExecuteTx(signatures []*UserSignature, tx *Transaction) (**TransactionEffects, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **TransactionEffects {
			return FfiConverterOptionalTransactionEffectsINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_execute_tx(
		_pointer,FfiConverterSequenceUserSignatureINSTANCE.Lower(signatures), FfiConverterTransactionINSTANCE.Lower(tx)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return the sequence number of the latest checkpoint that has been
// executed.
func (_self *GraphQlClient) LatestCheckpointSequenceNumber() (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_latest_checkpoint_sequence_number(
		_pointer,),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Lazily fetch the max page size
func (_self *GraphQlClient) MaxPageSize() (int32, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) C.int32_t {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_i32(handle, status)
			return res
		},
		// liftFn
		func(ffi C.int32_t) int32 {
			return FfiConverterInt32INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_max_page_size(
		_pointer,),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_i32(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_i32(handle)
		},
	)

	return res, err 
}

// Return the contents' JSON of an object that is a Move object.
//
// If the object does not exist (e.g., due to pruning), this will return
// `Ok(None)`. Similarly, if this is not an object but an address, it
// will return `Ok(None)`.
func (_self *GraphQlClient) MoveObjectContents(objectId *ObjectId, version *uint64) (*Value, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *Value {
			return FfiConverterOptionalTypeValueINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_move_object_contents(
		_pointer,FfiConverterObjectIdINSTANCE.Lower(objectId), FfiConverterOptionalUint64INSTANCE.Lower(version)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return the BCS of an object that is a Move object.
//
// If the object does not exist (e.g., due to pruning), this will return
// `Ok(None)`. Similarly, if this is not an object but an address, it
// will return `Ok(None)`.
func (_self *GraphQlClient) MoveObjectContentsBcs(objectId *ObjectId, version *uint64) (*[]byte, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *[]byte {
			return FfiConverterOptionalBytesINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_move_object_contents_bcs(
		_pointer,FfiConverterObjectIdINSTANCE.Lower(objectId), FfiConverterOptionalUint64INSTANCE.Lower(version)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return the normalized Move function data for the provided package,
// module, and function.
func (_self *GraphQlClient) NormalizedMoveFunction(varPackage string, module string, function string, version *uint64) (**MoveFunction, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **MoveFunction {
			return FfiConverterOptionalMoveFunctionINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_normalized_move_function(
		_pointer,FfiConverterStringINSTANCE.Lower(varPackage), FfiConverterStringINSTANCE.Lower(module), FfiConverterStringINSTANCE.Lower(function), FfiConverterOptionalUint64INSTANCE.Lower(version)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return the normalized Move module data for the provided module.
func (_self *GraphQlClient) NormalizedMoveModule(varPackage string, module string, paginationFilterEnums PaginationFilter, paginationFilterFriends PaginationFilter, paginationFilterFunctions PaginationFilter, paginationFilterStructs PaginationFilter, version *uint64) (**MoveModule, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **MoveModule {
			return FfiConverterOptionalMoveModuleINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_normalized_move_module(
		_pointer,FfiConverterStringINSTANCE.Lower(varPackage), FfiConverterStringINSTANCE.Lower(module), FfiConverterPaginationFilterINSTANCE.Lower(paginationFilterEnums), FfiConverterPaginationFilterINSTANCE.Lower(paginationFilterFriends), FfiConverterPaginationFilterINSTANCE.Lower(paginationFilterFunctions), FfiConverterPaginationFilterINSTANCE.Lower(paginationFilterStructs), FfiConverterOptionalUint64INSTANCE.Lower(version)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return an object based on the provided [`Address`].
//
// If the object does not exist (e.g., due to pruning), this will return
// `Ok(None)`. Similarly, if this is not an object but an address, it
// will return `Ok(None)`.
func (_self *GraphQlClient) Object(objectId *ObjectId, version *uint64) (**Object, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **Object {
			return FfiConverterOptionalObjectINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_object(
		_pointer,FfiConverterObjectIdINSTANCE.Lower(objectId), FfiConverterOptionalUint64INSTANCE.Lower(version)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return the object's bcs content [`Vec<u8>`] based on the provided
// [`Address`].
func (_self *GraphQlClient) ObjectBcs(objectId *ObjectId) (*[]byte, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *[]byte {
			return FfiConverterOptionalBytesINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_object_bcs(
		_pointer,FfiConverterObjectIdINSTANCE.Lower(objectId)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Return a page of objects based on the provided parameters.
//
// Use this function together with the [`ObjectFilter::owner`] to get the
// objects owned by an address.
//
// # Example
//
// ```rust,ignore
// let filter = ObjectFilter {
// type_: None,
// owner: Some(Address::from_str("test").unwrap().into()),
// object_ids: None,
// };
//
// let owned_objects = client.objects(None, None, Some(filter), None, None).await;
// ```
func (_self *GraphQlClient) Objects(paginationFilter PaginationFilter, filter **ObjectFilter) (*ObjectPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *ObjectPage {
			return FfiConverterObjectPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_objects(
		_pointer,FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalObjectFilterINSTANCE.Lower(filter)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// The package corresponding to the given address (at the optionally given
// version). When no version is given, the package is loaded directly
// from the address given. Otherwise, the address is translated before
// loading to point to the package whose original ID matches
// the package at address, but whose version is version. For non-system
// packages, this might result in a different address than address
// because different versions of a package, introduced by upgrades,
// exist at distinct addresses.
//
// Note that this interpretation of version is different from a historical
// object read (the interpretation of version for the object query).
func (_self *GraphQlClient) Package(address *Address, version *uint64) (**MovePackage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **MovePackage {
			return FfiConverterOptionalMovePackageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_package(
		_pointer,FfiConverterAddressINSTANCE.Lower(address), FfiConverterOptionalUint64INSTANCE.Lower(version)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Fetch the latest version of the package at address.
// This corresponds to the package with the highest version that shares its
// original ID with the package at address.
func (_self *GraphQlClient) PackageLatest(address *Address) (**MovePackage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **MovePackage {
			return FfiConverterOptionalMovePackageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_package_latest(
		_pointer,FfiConverterAddressINSTANCE.Lower(address)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Fetch all versions of package at address (packages that share this
// package's original ID), optionally bounding the versions exclusively
// from below with afterVersion, or from above with beforeVersion.
func (_self *GraphQlClient) PackageVersions(address *Address, paginationFilter PaginationFilter, afterVersion *uint64, beforeVersion *uint64) (*MovePackagePage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *MovePackagePage {
			return FfiConverterMovePackagePageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_package_versions(
		_pointer,FfiConverterAddressINSTANCE.Lower(address), FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalUint64INSTANCE.Lower(afterVersion), FfiConverterOptionalUint64INSTANCE.Lower(beforeVersion)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// The Move packages that exist in the network, optionally filtered to be
// strictly before beforeCheckpoint and/or strictly after
// afterCheckpoint.
//
// This query returns all versions of a given user package that appear
// between the specified checkpoints, but only records the latest
// versions of system packages.
func (_self *GraphQlClient) Packages(paginationFilter PaginationFilter, afterCheckpoint *uint64, beforeCheckpoint *uint64) (*MovePackagePage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *MovePackagePage {
			return FfiConverterMovePackagePageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_packages(
		_pointer,FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalUint64INSTANCE.Lower(afterCheckpoint), FfiConverterOptionalUint64INSTANCE.Lower(beforeCheckpoint)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Get the protocol configuration.
func (_self *GraphQlClient) ProtocolConfig(version *uint64) (**ProtocolConfigs, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **ProtocolConfigs {
			return FfiConverterOptionalProtocolConfigsINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_protocol_config(
		_pointer,FfiConverterOptionalUint64INSTANCE.Lower(version)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get the reference gas price for the provided epoch or the last known one
// if no epoch is provided.
//
// This will return `Ok(None)` if the epoch requested is not available in
// the GraphQL service (e.g., due to pruning).
func (_self *GraphQlClient) ReferenceGasPrice(epoch *uint64) (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_reference_gas_price(
		_pointer,FfiConverterOptionalUint64INSTANCE.Lower(epoch)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get the GraphQL service configuration, including complexity limits, read
// and mutation limits, supported versions, and others.
func (_self *GraphQlClient) ServiceConfig() (*ServiceConfig, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *ServiceConfig {
			return FfiConverterServiceConfigINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_service_config(
		_pointer,),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Set the server address for the GraphQL GraphQL client. It should be a
// valid URL with a host and optionally a port number.
func (_self *GraphQlClient) SetRpcServer(server string) error {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 _, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_iota_sdk_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_set_rpc_server(
		_pointer,FfiConverterStringINSTANCE.Lower(server)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_void(handle)
		},
	)

	return err 
}

// Get total supply for the coin type.
func (_self *GraphQlClient) TotalSupply(coinType string) (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_total_supply(
		_pointer,FfiConverterStringINSTANCE.Lower(coinType)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// The total number of transaction blocks in the network by the end of the
// last known checkpoint.
func (_self *GraphQlClient) TotalTransactionBlocks() (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_total_transaction_blocks(
		_pointer,),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// The total number of transaction blocks in the network by the end of the
// provided checkpoint digest.
func (_self *GraphQlClient) TotalTransactionBlocksByDigest(digest *CheckpointContentsDigest) (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_total_transaction_blocks_by_digest(
		_pointer,FfiConverterCheckpointContentsDigestINSTANCE.Lower(digest)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// The total number of transaction blocks in the network by the end of the
// provided checkpoint sequence number.
func (_self *GraphQlClient) TotalTransactionBlocksBySeqNum(seqNum uint64) (*uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) *uint64 {
			return FfiConverterOptionalUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_total_transaction_blocks_by_seq_num(
		_pointer,FfiConverterUint64INSTANCE.Lower(seqNum)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get a transaction by its digest.
func (_self *GraphQlClient) Transaction(digest *TransactionDigest) (**SignedTransaction, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **SignedTransaction {
			return FfiConverterOptionalSignedTransactionINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_transaction(
		_pointer,FfiConverterTransactionDigestINSTANCE.Lower(digest)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get a transaction's data and effects by its digest.
func (_self *GraphQlClient) TransactionDataEffects(digest *TransactionDigest) (**TransactionDataEffects, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **TransactionDataEffects {
			return FfiConverterOptionalTransactionDataEffectsINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_transaction_data_effects(
		_pointer,FfiConverterTransactionDigestINSTANCE.Lower(digest)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get a transaction's effects by its digest.
func (_self *GraphQlClient) TransactionEffects(digest *TransactionDigest) (**TransactionEffects, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer {
		inner: res,
	}
		},
		// liftFn
		func(ffi RustBufferI) **TransactionEffects {
			return FfiConverterOptionalTransactionEffectsINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_transaction_effects(
		_pointer,FfiConverterTransactionDigestINSTANCE.Lower(digest)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res, err 
}

// Get a page of transactions based on the provided filters.
func (_self *GraphQlClient) Transactions(paginationFilter PaginationFilter, filter *TransactionsFilter) (*SignedTransactionPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *SignedTransactionPage {
			return FfiConverterSignedTransactionPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_transactions(
		_pointer,FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalTransactionsFilterINSTANCE.Lower(filter)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Get a page of transactions' data and effects based on the provided
// filters.
func (_self *GraphQlClient) TransactionsDataEffects(paginationFilter PaginationFilter, filter *TransactionsFilter) (*TransactionDataEffectsPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *TransactionDataEffectsPage {
			return FfiConverterTransactionDataEffectsPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_transactions_data_effects(
		_pointer,FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalTransactionsFilterINSTANCE.Lower(filter)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}

// Get a page of transactions' effects based on the provided filters.
func (_self *GraphQlClient) TransactionsEffects(paginationFilter PaginationFilter, filter *TransactionsFilter) (*TransactionEffectsPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*GraphQlClient")
	defer _self.ffiObject.decrementPointer()
	 res, err :=uniffiRustCallAsync[SdkFfiError](
        FfiConverterSdkFfiErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_iota_sdk_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *TransactionEffectsPage {
			return FfiConverterTransactionEffectsPageINSTANCE.Lift(ffi)
		},
		C.uniffi_iota_sdk_ffi_fn_method_graphqlclient_transactions_effects(
		_pointer,FfiConverterPaginationFilterINSTANCE.Lower(paginationFilter), FfiConverterOptionalTransactionsFilterINSTANCE.Lower(filter)),
		// pollFn
		func (handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func (handle C.uint64_t) {
			C.ffi_iota_sdk_ffi_rust_future_free_pointer(handle)
		},
	)

	return res, err 
}
func (object *GraphQlClient) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterGraphQlClient struct {}

var FfiConverterGraphQlClientINSTANCE = FfiConverterGraphQlClient{}


func (c FfiConverterGraphQlClient) Lift(pointer unsafe.Pointer) *GraphQlClient {
	result := &GraphQlClient {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_graphqlclient(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_graphqlclient(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*GraphQlClient).Destroy)
	return result
}

func (c FfiConverterGraphQlClient) Read(reader io.Reader) *GraphQlClient {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterGraphQlClient) Lower(value *GraphQlClient) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*GraphQlClient")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterGraphQlClient) Write(writer io.Writer, value *GraphQlClient) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerGraphQlClient struct {}

func (_ FfiDestroyerGraphQlClient) Destroy(value *GraphQlClient) {
		value.Destroy()
}



type MoveFunctionInterface interface {
}
type MoveFunction struct {
	ffiObject FfiObject
}



func (object *MoveFunction) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterMoveFunction struct {}

var FfiConverterMoveFunctionINSTANCE = FfiConverterMoveFunction{}


func (c FfiConverterMoveFunction) Lift(pointer unsafe.Pointer) *MoveFunction {
	result := &MoveFunction {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_movefunction(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_movefunction(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*MoveFunction).Destroy)
	return result
}

func (c FfiConverterMoveFunction) Read(reader io.Reader) *MoveFunction {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterMoveFunction) Lower(value *MoveFunction) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*MoveFunction")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterMoveFunction) Write(writer io.Writer, value *MoveFunction) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerMoveFunction struct {}

func (_ FfiDestroyerMoveFunction) Destroy(value *MoveFunction) {
		value.Destroy()
}



type MoveModuleInterface interface {
}
type MoveModule struct {
	ffiObject FfiObject
}



func (object *MoveModule) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterMoveModule struct {}

var FfiConverterMoveModuleINSTANCE = FfiConverterMoveModule{}


func (c FfiConverterMoveModule) Lift(pointer unsafe.Pointer) *MoveModule {
	result := &MoveModule {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_movemodule(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_movemodule(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*MoveModule).Destroy)
	return result
}

func (c FfiConverterMoveModule) Read(reader io.Reader) *MoveModule {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterMoveModule) Lower(value *MoveModule) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*MoveModule")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterMoveModule) Write(writer io.Writer, value *MoveModule) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerMoveModule struct {}

func (_ FfiDestroyerMoveModule) Destroy(value *MoveModule) {
		value.Destroy()
}



type MovePackageInterface interface {
}
type MovePackage struct {
	ffiObject FfiObject
}



func (object *MovePackage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterMovePackage struct {}

var FfiConverterMovePackageINSTANCE = FfiConverterMovePackage{}


func (c FfiConverterMovePackage) Lift(pointer unsafe.Pointer) *MovePackage {
	result := &MovePackage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_movepackage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_movepackage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*MovePackage).Destroy)
	return result
}

func (c FfiConverterMovePackage) Read(reader io.Reader) *MovePackage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterMovePackage) Lower(value *MovePackage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*MovePackage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterMovePackage) Write(writer io.Writer, value *MovePackage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerMovePackage struct {}

func (_ FfiDestroyerMovePackage) Destroy(value *MovePackage) {
		value.Destroy()
}



type MovePackagePageInterface interface {
	Data() []*MovePackage
	IsEmpty() bool
	PageInfo() *PageInfo
}
type MovePackagePage struct {
	ffiObject FfiObject
}




func (_self *MovePackagePage) Data() []*MovePackage {
	_pointer := _self.ffiObject.incrementPointer("*MovePackagePage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceMovePackageINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_movepackagepage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *MovePackagePage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*MovePackagePage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_movepackagepage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *MovePackagePage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*MovePackagePage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_movepackagepage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *MovePackagePage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterMovePackagePage struct {}

var FfiConverterMovePackagePageINSTANCE = FfiConverterMovePackagePage{}


func (c FfiConverterMovePackagePage) Lift(pointer unsafe.Pointer) *MovePackagePage {
	result := &MovePackagePage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_movepackagepage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_movepackagepage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*MovePackagePage).Destroy)
	return result
}

func (c FfiConverterMovePackagePage) Read(reader io.Reader) *MovePackagePage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterMovePackagePage) Lower(value *MovePackagePage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*MovePackagePage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterMovePackagePage) Write(writer io.Writer, value *MovePackagePage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerMovePackagePage struct {}

func (_ FfiDestroyerMovePackagePage) Destroy(value *MovePackagePage) {
		value.Destroy()
}



type MoveStructInterface interface {
}
type MoveStruct struct {
	ffiObject FfiObject
}



func (object *MoveStruct) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterMoveStruct struct {}

var FfiConverterMoveStructINSTANCE = FfiConverterMoveStruct{}


func (c FfiConverterMoveStruct) Lift(pointer unsafe.Pointer) *MoveStruct {
	result := &MoveStruct {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_movestruct(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_movestruct(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*MoveStruct).Destroy)
	return result
}

func (c FfiConverterMoveStruct) Read(reader io.Reader) *MoveStruct {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterMoveStruct) Lower(value *MoveStruct) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*MoveStruct")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterMoveStruct) Write(writer io.Writer, value *MoveStruct) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerMoveStruct struct {}

func (_ FfiDestroyerMoveStruct) Destroy(value *MoveStruct) {
		value.Destroy()
}



// An object on the IOTA blockchain
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// object = object-data owner digest u64
// ```
type ObjectInterface interface {
	// Try to interpret this object as a move struct
	AsStruct() **MoveStruct
	// Return this object's data
	Data() *ObjectData
	// Return this object's id
	ObjectId() *ObjectId
	// Return this object's type
	ObjectType() *ObjectType
	// Return this object's owner
	Owner() *Owner
	// Return the digest of the transaction that last modified this object
	PreviousTransaction() *TransactionDigest
	// Return the storage rebate locked in this object
	//
	// Storage rebates are credited to the gas coin used in a transaction that
	// deletes this object.
	StorageRebate() uint64
	// Return this object's version
	Version() uint64
}
// An object on the IOTA blockchain
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// object = object-data owner digest u64
// ```
type Object struct {
	ffiObject FfiObject
}
func NewObject(data *ObjectData, owner *Owner, previousTransaction *TransactionDigest, storageRebate uint64) *Object {
	return FfiConverterObjectINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_object_new(FfiConverterObjectDataINSTANCE.Lower(data), FfiConverterOwnerINSTANCE.Lower(owner), FfiConverterTransactionDigestINSTANCE.Lower(previousTransaction), FfiConverterUint64INSTANCE.Lower(storageRebate),_uniffiStatus)
	}))
}




// Try to interpret this object as a move struct
func (_self *Object) AsStruct() **MoveStruct {
	_pointer := _self.ffiObject.incrementPointer("*Object")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterOptionalMoveStructINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_object_as_struct(
		_pointer,_uniffiStatus),
	}
	}))
}

// Return this object's data
func (_self *Object) Data() *ObjectData {
	_pointer := _self.ffiObject.incrementPointer("*Object")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterObjectDataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_object_data(
		_pointer,_uniffiStatus)
	}))
}

// Return this object's id
func (_self *Object) ObjectId() *ObjectId {
	_pointer := _self.ffiObject.incrementPointer("*Object")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterObjectIdINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_object_object_id(
		_pointer,_uniffiStatus)
	}))
}

// Return this object's type
func (_self *Object) ObjectType() *ObjectType {
	_pointer := _self.ffiObject.incrementPointer("*Object")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterObjectTypeINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_object_object_type(
		_pointer,_uniffiStatus)
	}))
}

// Return this object's owner
func (_self *Object) Owner() *Owner {
	_pointer := _self.ffiObject.incrementPointer("*Object")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterOwnerINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_object_owner(
		_pointer,_uniffiStatus)
	}))
}

// Return the digest of the transaction that last modified this object
func (_self *Object) PreviousTransaction() *TransactionDigest {
	_pointer := _self.ffiObject.incrementPointer("*Object")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterTransactionDigestINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_object_previous_transaction(
		_pointer,_uniffiStatus)
	}))
}

// Return the storage rebate locked in this object
//
// Storage rebates are credited to the gas coin used in a transaction that
// deletes this object.
func (_self *Object) StorageRebate() uint64 {
	_pointer := _self.ffiObject.incrementPointer("*Object")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterUint64INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_iota_sdk_ffi_fn_method_object_storage_rebate(
		_pointer,_uniffiStatus)
	}))
}

// Return this object's version
func (_self *Object) Version() uint64 {
	_pointer := _self.ffiObject.incrementPointer("*Object")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterUint64INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_iota_sdk_ffi_fn_method_object_version(
		_pointer,_uniffiStatus)
	}))
}
func (object *Object) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterObject struct {}

var FfiConverterObjectINSTANCE = FfiConverterObject{}


func (c FfiConverterObject) Lift(pointer unsafe.Pointer) *Object {
	result := &Object {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_object(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_object(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Object).Destroy)
	return result
}

func (c FfiConverterObject) Read(reader io.Reader) *Object {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterObject) Lower(value *Object) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Object")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterObject) Write(writer io.Writer, value *Object) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerObject struct {}

func (_ FfiDestroyerObject) Destroy(value *Object) {
		value.Destroy()
}



type ObjectDataInterface interface {
}
type ObjectData struct {
	ffiObject FfiObject
}



func (object *ObjectData) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterObjectData struct {}

var FfiConverterObjectDataINSTANCE = FfiConverterObjectData{}


func (c FfiConverterObjectData) Lift(pointer unsafe.Pointer) *ObjectData {
	result := &ObjectData {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_objectdata(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_objectdata(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ObjectData).Destroy)
	return result
}

func (c FfiConverterObjectData) Read(reader io.Reader) *ObjectData {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterObjectData) Lower(value *ObjectData) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ObjectData")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterObjectData) Write(writer io.Writer, value *ObjectData) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerObjectData struct {}

func (_ FfiDestroyerObjectData) Destroy(value *ObjectData) {
		value.Destroy()
}



type ObjectDigestInterface interface {
}
type ObjectDigest struct {
	ffiObject FfiObject
}



func (object *ObjectDigest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterObjectDigest struct {}

var FfiConverterObjectDigestINSTANCE = FfiConverterObjectDigest{}


func (c FfiConverterObjectDigest) Lift(pointer unsafe.Pointer) *ObjectDigest {
	result := &ObjectDigest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_objectdigest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_objectdigest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ObjectDigest).Destroy)
	return result
}

func (c FfiConverterObjectDigest) Read(reader io.Reader) *ObjectDigest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterObjectDigest) Lower(value *ObjectDigest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ObjectDigest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterObjectDigest) Write(writer io.Writer, value *ObjectDigest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerObjectDigest struct {}

func (_ FfiDestroyerObjectDigest) Destroy(value *ObjectDigest) {
		value.Destroy()
}



type ObjectFilterInterface interface {
}
type ObjectFilter struct {
	ffiObject FfiObject
}



func (object *ObjectFilter) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterObjectFilter struct {}

var FfiConverterObjectFilterINSTANCE = FfiConverterObjectFilter{}


func (c FfiConverterObjectFilter) Lift(pointer unsafe.Pointer) *ObjectFilter {
	result := &ObjectFilter {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_objectfilter(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_objectfilter(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ObjectFilter).Destroy)
	return result
}

func (c FfiConverterObjectFilter) Read(reader io.Reader) *ObjectFilter {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterObjectFilter) Lower(value *ObjectFilter) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ObjectFilter")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterObjectFilter) Write(writer io.Writer, value *ObjectFilter) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerObjectFilter struct {}

func (_ FfiDestroyerObjectFilter) Destroy(value *ObjectFilter) {
		value.Destroy()
}



// An `ObjectId` is a 32-byte identifier used to uniquely identify an object on
// the IOTA blockchain.
//
// ## Relationship to Address
//
// [`Address`]es and [`ObjectId`]s share the same 32-byte addressable space but
// are derived leveraging different domain-separator values to ensure,
// cryptographically, that there won't be any overlap, e.g. there can't be a
// valid `Object` whose `ObjectId` is equal to that of the `Address` of a user
// account.
//
// # BCS
//
// An `ObjectId`'s BCS serialized form is defined by the following:
//
// ```text
// object-id = 32*OCTET
// ```
type ObjectIdInterface interface {
	ToAddress() *Address
	ToBytes() []byte
	ToHex() string
}
// An `ObjectId` is a 32-byte identifier used to uniquely identify an object on
// the IOTA blockchain.
//
// ## Relationship to Address
//
// [`Address`]es and [`ObjectId`]s share the same 32-byte addressable space but
// are derived leveraging different domain-separator values to ensure,
// cryptographically, that there won't be any overlap, e.g. there can't be a
// valid `Object` whose `ObjectId` is equal to that of the `Address` of a user
// account.
//
// # BCS
//
// An `ObjectId`'s BCS serialized form is defined by the following:
//
// ```text
// object-id = 32*OCTET
// ```
type ObjectId struct {
	ffiObject FfiObject
}


func ObjectIdFromBytes(bytes []byte) (*ObjectId, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_objectid_from_bytes(FfiConverterBytesINSTANCE.Lower(bytes),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *ObjectId
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterObjectIdINSTANCE.Lift(_uniffiRV), nil
		}
}

func ObjectIdFromHex(hex string) (*ObjectId, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_objectid_from_hex(FfiConverterStringINSTANCE.Lower(hex),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *ObjectId
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterObjectIdINSTANCE.Lift(_uniffiRV), nil
		}
}



func (_self *ObjectId) ToAddress() *Address {
	_pointer := _self.ffiObject.incrementPointer("*ObjectId")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterAddressINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_objectid_to_address(
		_pointer,_uniffiStatus)
	}))
}

func (_self *ObjectId) ToBytes() []byte {
	_pointer := _self.ffiObject.incrementPointer("*ObjectId")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_objectid_to_bytes(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *ObjectId) ToHex() string {
	_pointer := _self.ffiObject.incrementPointer("*ObjectId")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_objectid_to_hex(
		_pointer,_uniffiStatus),
	}
	}))
}
func (object *ObjectId) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterObjectId struct {}

var FfiConverterObjectIdINSTANCE = FfiConverterObjectId{}


func (c FfiConverterObjectId) Lift(pointer unsafe.Pointer) *ObjectId {
	result := &ObjectId {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_objectid(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_objectid(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ObjectId).Destroy)
	return result
}

func (c FfiConverterObjectId) Read(reader io.Reader) *ObjectId {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterObjectId) Lower(value *ObjectId) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ObjectId")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterObjectId) Write(writer io.Writer, value *ObjectId) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerObjectId struct {}

func (_ FfiDestroyerObjectId) Destroy(value *ObjectId) {
		value.Destroy()
}



type ObjectPageInterface interface {
	Data() []*Object
	IsEmpty() bool
	PageInfo() *PageInfo
}
type ObjectPage struct {
	ffiObject FfiObject
}




func (_self *ObjectPage) Data() []*Object {
	_pointer := _self.ffiObject.incrementPointer("*ObjectPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceObjectINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_objectpage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *ObjectPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*ObjectPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_objectpage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *ObjectPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*ObjectPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_objectpage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *ObjectPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterObjectPage struct {}

var FfiConverterObjectPageINSTANCE = FfiConverterObjectPage{}


func (c FfiConverterObjectPage) Lift(pointer unsafe.Pointer) *ObjectPage {
	result := &ObjectPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_objectpage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_objectpage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ObjectPage).Destroy)
	return result
}

func (c FfiConverterObjectPage) Read(reader io.Reader) *ObjectPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterObjectPage) Lower(value *ObjectPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ObjectPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterObjectPage) Write(writer io.Writer, value *ObjectPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerObjectPage struct {}

func (_ FfiDestroyerObjectPage) Destroy(value *ObjectPage) {
		value.Destroy()
}



type ObjectRefInterface interface {
}
type ObjectRef struct {
	ffiObject FfiObject
}



func (object *ObjectRef) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterObjectRef struct {}

var FfiConverterObjectRefINSTANCE = FfiConverterObjectRef{}


func (c FfiConverterObjectRef) Lift(pointer unsafe.Pointer) *ObjectRef {
	result := &ObjectRef {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_objectref(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_objectref(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ObjectRef).Destroy)
	return result
}

func (c FfiConverterObjectRef) Read(reader io.Reader) *ObjectRef {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterObjectRef) Lower(value *ObjectRef) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ObjectRef")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterObjectRef) Write(writer io.Writer, value *ObjectRef) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerObjectRef struct {}

func (_ FfiDestroyerObjectRef) Destroy(value *ObjectRef) {
		value.Destroy()
}



type ObjectTypeInterface interface {
}
type ObjectType struct {
	ffiObject FfiObject
}



func (object *ObjectType) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterObjectType struct {}

var FfiConverterObjectTypeINSTANCE = FfiConverterObjectType{}


func (c FfiConverterObjectType) Lift(pointer unsafe.Pointer) *ObjectType {
	result := &ObjectType {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_objecttype(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_objecttype(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ObjectType).Destroy)
	return result
}

func (c FfiConverterObjectType) Read(reader io.Reader) *ObjectType {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterObjectType) Lower(value *ObjectType) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ObjectType")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterObjectType) Write(writer io.Writer, value *ObjectType) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerObjectType struct {}

func (_ FfiDestroyerObjectType) Destroy(value *ObjectType) {
		value.Destroy()
}



type OwnerInterface interface {
}
type Owner struct {
	ffiObject FfiObject
}



func (object *Owner) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterOwner struct {}

var FfiConverterOwnerINSTANCE = FfiConverterOwner{}


func (c FfiConverterOwner) Lift(pointer unsafe.Pointer) *Owner {
	result := &Owner {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_owner(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_owner(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Owner).Destroy)
	return result
}

func (c FfiConverterOwner) Read(reader io.Reader) *Owner {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterOwner) Lower(value *Owner) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Owner")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterOwner) Write(writer io.Writer, value *Owner) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerOwner struct {}

func (_ FfiDestroyerOwner) Destroy(value *Owner) {
		value.Destroy()
}



type PageInfoInterface interface {
}
type PageInfo struct {
	ffiObject FfiObject
}



func (object *PageInfo) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterPageInfo struct {}

var FfiConverterPageInfoINSTANCE = FfiConverterPageInfo{}


func (c FfiConverterPageInfo) Lift(pointer unsafe.Pointer) *PageInfo {
	result := &PageInfo {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_pageinfo(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_pageinfo(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*PageInfo).Destroy)
	return result
}

func (c FfiConverterPageInfo) Read(reader io.Reader) *PageInfo {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterPageInfo) Lower(value *PageInfo) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*PageInfo")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterPageInfo) Write(writer io.Writer, value *PageInfo) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerPageInfo struct {}

func (_ FfiDestroyerPageInfo) Destroy(value *PageInfo) {
		value.Destroy()
}



type ProgrammableTransactionInterface interface {
}
type ProgrammableTransaction struct {
	ffiObject FfiObject
}



func (object *ProgrammableTransaction) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterProgrammableTransaction struct {}

var FfiConverterProgrammableTransactionINSTANCE = FfiConverterProgrammableTransaction{}


func (c FfiConverterProgrammableTransaction) Lift(pointer unsafe.Pointer) *ProgrammableTransaction {
	result := &ProgrammableTransaction {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_programmabletransaction(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_programmabletransaction(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ProgrammableTransaction).Destroy)
	return result
}

func (c FfiConverterProgrammableTransaction) Read(reader io.Reader) *ProgrammableTransaction {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterProgrammableTransaction) Lower(value *ProgrammableTransaction) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ProgrammableTransaction")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterProgrammableTransaction) Write(writer io.Writer, value *ProgrammableTransaction) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerProgrammableTransaction struct {}

func (_ FfiDestroyerProgrammableTransaction) Destroy(value *ProgrammableTransaction) {
		value.Destroy()
}



type ProtocolConfigsInterface interface {
}
type ProtocolConfigs struct {
	ffiObject FfiObject
}



func (object *ProtocolConfigs) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterProtocolConfigs struct {}

var FfiConverterProtocolConfigsINSTANCE = FfiConverterProtocolConfigs{}


func (c FfiConverterProtocolConfigs) Lift(pointer unsafe.Pointer) *ProtocolConfigs {
	result := &ProtocolConfigs {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_protocolconfigs(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_protocolconfigs(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ProtocolConfigs).Destroy)
	return result
}

func (c FfiConverterProtocolConfigs) Read(reader io.Reader) *ProtocolConfigs {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterProtocolConfigs) Lower(value *ProtocolConfigs) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ProtocolConfigs")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterProtocolConfigs) Write(writer io.Writer, value *ProtocolConfigs) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerProtocolConfigs struct {}

func (_ FfiDestroyerProtocolConfigs) Destroy(value *ProtocolConfigs) {
		value.Destroy()
}



type RandomnessStateUpdateInterface interface {
}
type RandomnessStateUpdate struct {
	ffiObject FfiObject
}



func (object *RandomnessStateUpdate) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterRandomnessStateUpdate struct {}

var FfiConverterRandomnessStateUpdateINSTANCE = FfiConverterRandomnessStateUpdate{}


func (c FfiConverterRandomnessStateUpdate) Lift(pointer unsafe.Pointer) *RandomnessStateUpdate {
	result := &RandomnessStateUpdate {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_randomnessstateupdate(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_randomnessstateupdate(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*RandomnessStateUpdate).Destroy)
	return result
}

func (c FfiConverterRandomnessStateUpdate) Read(reader io.Reader) *RandomnessStateUpdate {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterRandomnessStateUpdate) Lower(value *RandomnessStateUpdate) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*RandomnessStateUpdate")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterRandomnessStateUpdate) Write(writer io.Writer, value *RandomnessStateUpdate) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerRandomnessStateUpdate struct {}

func (_ FfiDestroyerRandomnessStateUpdate) Destroy(value *RandomnessStateUpdate) {
		value.Destroy()
}



// A secp256k1 signature.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// secp256k1-signature = 64OCTECT
// ```
type Secp256k1PublicKeyInterface interface {
	ToBytes() []byte
}
// A secp256k1 signature.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// secp256k1-signature = 64OCTECT
// ```
type Secp256k1PublicKey struct {
	ffiObject FfiObject
}


func Secp256k1PublicKeyFromBytes(bytes []byte) (*Secp256k1PublicKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_secp256k1publickey_from_bytes(FfiConverterBytesINSTANCE.Lower(bytes),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Secp256k1PublicKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSecp256k1PublicKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

func Secp256k1PublicKeyFromStr(s string) (*Secp256k1PublicKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_secp256k1publickey_from_str(FfiConverterStringINSTANCE.Lower(s),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Secp256k1PublicKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSecp256k1PublicKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

func Secp256k1PublicKeyGenerate() *Secp256k1PublicKey {
	return FfiConverterSecp256k1PublicKeyINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_secp256k1publickey_generate(_uniffiStatus)
	}))
}



func (_self *Secp256k1PublicKey) ToBytes() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Secp256k1PublicKey")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_secp256k1publickey_to_bytes(
		_pointer,_uniffiStatus),
	}
	}))
}
func (object *Secp256k1PublicKey) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterSecp256k1PublicKey struct {}

var FfiConverterSecp256k1PublicKeyINSTANCE = FfiConverterSecp256k1PublicKey{}


func (c FfiConverterSecp256k1PublicKey) Lift(pointer unsafe.Pointer) *Secp256k1PublicKey {
	result := &Secp256k1PublicKey {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_secp256k1publickey(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_secp256k1publickey(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Secp256k1PublicKey).Destroy)
	return result
}

func (c FfiConverterSecp256k1PublicKey) Read(reader io.Reader) *Secp256k1PublicKey {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterSecp256k1PublicKey) Lower(value *Secp256k1PublicKey) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Secp256k1PublicKey")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterSecp256k1PublicKey) Write(writer io.Writer, value *Secp256k1PublicKey) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerSecp256k1PublicKey struct {}

func (_ FfiDestroyerSecp256k1PublicKey) Destroy(value *Secp256k1PublicKey) {
		value.Destroy()
}



// A secp256r1 signature.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// secp256r1-signature = 64OCTECT
// ```
type Secp256r1PublicKeyInterface interface {
	ToBytes() []byte
}
// A secp256r1 signature.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// secp256r1-signature = 64OCTECT
// ```
type Secp256r1PublicKey struct {
	ffiObject FfiObject
}


func Secp256r1PublicKeyFromBytes(bytes []byte) (*Secp256r1PublicKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_secp256r1publickey_from_bytes(FfiConverterBytesINSTANCE.Lower(bytes),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Secp256r1PublicKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSecp256r1PublicKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

func Secp256r1PublicKeyFromStr(s string) (*Secp256r1PublicKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[SdkFfiError](FfiConverterSdkFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_secp256r1publickey_from_str(FfiConverterStringINSTANCE.Lower(s),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *Secp256r1PublicKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSecp256r1PublicKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

func Secp256r1PublicKeyGenerate() *Secp256r1PublicKey {
	return FfiConverterSecp256r1PublicKeyINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_secp256r1publickey_generate(_uniffiStatus)
	}))
}



func (_self *Secp256r1PublicKey) ToBytes() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Secp256r1PublicKey")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_secp256r1publickey_to_bytes(
		_pointer,_uniffiStatus),
	}
	}))
}
func (object *Secp256r1PublicKey) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterSecp256r1PublicKey struct {}

var FfiConverterSecp256r1PublicKeyINSTANCE = FfiConverterSecp256r1PublicKey{}


func (c FfiConverterSecp256r1PublicKey) Lift(pointer unsafe.Pointer) *Secp256r1PublicKey {
	result := &Secp256r1PublicKey {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_secp256r1publickey(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_secp256r1publickey(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Secp256r1PublicKey).Destroy)
	return result
}

func (c FfiConverterSecp256r1PublicKey) Read(reader io.Reader) *Secp256r1PublicKey {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterSecp256r1PublicKey) Lower(value *Secp256r1PublicKey) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Secp256r1PublicKey")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterSecp256r1PublicKey) Write(writer io.Writer, value *Secp256r1PublicKey) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerSecp256r1PublicKey struct {}

func (_ FfiDestroyerSecp256r1PublicKey) Destroy(value *Secp256r1PublicKey) {
		value.Destroy()
}



type ServiceConfigInterface interface {
}
type ServiceConfig struct {
	ffiObject FfiObject
}



func (object *ServiceConfig) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterServiceConfig struct {}

var FfiConverterServiceConfigINSTANCE = FfiConverterServiceConfig{}


func (c FfiConverterServiceConfig) Lift(pointer unsafe.Pointer) *ServiceConfig {
	result := &ServiceConfig {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_serviceconfig(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_serviceconfig(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ServiceConfig).Destroy)
	return result
}

func (c FfiConverterServiceConfig) Read(reader io.Reader) *ServiceConfig {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterServiceConfig) Lower(value *ServiceConfig) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ServiceConfig")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterServiceConfig) Write(writer io.Writer, value *ServiceConfig) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerServiceConfig struct {}

func (_ FfiDestroyerServiceConfig) Destroy(value *ServiceConfig) {
		value.Destroy()
}



type SignedTransactionInterface interface {
	Signatures() []*UserSignature
	Transaction() *Transaction
}
type SignedTransaction struct {
	ffiObject FfiObject
}
func NewSignedTransaction(transaction *Transaction, signatures []*UserSignature) *SignedTransaction {
	return FfiConverterSignedTransactionINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_signedtransaction_new(FfiConverterTransactionINSTANCE.Lower(transaction), FfiConverterSequenceUserSignatureINSTANCE.Lower(signatures),_uniffiStatus)
	}))
}




func (_self *SignedTransaction) Signatures() []*UserSignature {
	_pointer := _self.ffiObject.incrementPointer("*SignedTransaction")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceUserSignatureINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_signedtransaction_signatures(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *SignedTransaction) Transaction() *Transaction {
	_pointer := _self.ffiObject.incrementPointer("*SignedTransaction")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterTransactionINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_signedtransaction_transaction(
		_pointer,_uniffiStatus)
	}))
}
func (object *SignedTransaction) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterSignedTransaction struct {}

var FfiConverterSignedTransactionINSTANCE = FfiConverterSignedTransaction{}


func (c FfiConverterSignedTransaction) Lift(pointer unsafe.Pointer) *SignedTransaction {
	result := &SignedTransaction {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_signedtransaction(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_signedtransaction(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*SignedTransaction).Destroy)
	return result
}

func (c FfiConverterSignedTransaction) Read(reader io.Reader) *SignedTransaction {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterSignedTransaction) Lower(value *SignedTransaction) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*SignedTransaction")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterSignedTransaction) Write(writer io.Writer, value *SignedTransaction) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerSignedTransaction struct {}

func (_ FfiDestroyerSignedTransaction) Destroy(value *SignedTransaction) {
		value.Destroy()
}



type SignedTransactionPageInterface interface {
	Data() []*SignedTransaction
	IsEmpty() bool
	PageInfo() *PageInfo
}
type SignedTransactionPage struct {
	ffiObject FfiObject
}




func (_self *SignedTransactionPage) Data() []*SignedTransaction {
	_pointer := _self.ffiObject.incrementPointer("*SignedTransactionPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceSignedTransactionINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_signedtransactionpage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *SignedTransactionPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*SignedTransactionPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_signedtransactionpage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *SignedTransactionPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*SignedTransactionPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_signedtransactionpage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *SignedTransactionPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterSignedTransactionPage struct {}

var FfiConverterSignedTransactionPageINSTANCE = FfiConverterSignedTransactionPage{}


func (c FfiConverterSignedTransactionPage) Lift(pointer unsafe.Pointer) *SignedTransactionPage {
	result := &SignedTransactionPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_signedtransactionpage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_signedtransactionpage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*SignedTransactionPage).Destroy)
	return result
}

func (c FfiConverterSignedTransactionPage) Read(reader io.Reader) *SignedTransactionPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterSignedTransactionPage) Lower(value *SignedTransactionPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*SignedTransactionPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterSignedTransactionPage) Write(writer io.Writer, value *SignedTransactionPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerSignedTransactionPage struct {}

func (_ FfiDestroyerSignedTransactionPage) Destroy(value *SignedTransactionPage) {
		value.Destroy()
}



// A transaction
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// transaction = %x00 transaction-v1
//
// transaction-v1 = transaction-kind address gas-payment transaction-expiration
// ```
type TransactionInterface interface {
	Expiration() *TransactionExpiration
	GasPayment() GasPayment
	Kind() *TransactionKind
	Sender() *Address
}
// A transaction
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// transaction = %x00 transaction-v1
//
// transaction-v1 = transaction-kind address gas-payment transaction-expiration
// ```
type Transaction struct {
	ffiObject FfiObject
}
func NewTransaction(kind *TransactionKind, sender *Address, gasPayment GasPayment, expiration *TransactionExpiration) *Transaction {
	return FfiConverterTransactionINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_transaction_new(FfiConverterTransactionKindINSTANCE.Lower(kind), FfiConverterAddressINSTANCE.Lower(sender), FfiConverterGasPaymentINSTANCE.Lower(gasPayment), FfiConverterTransactionExpirationINSTANCE.Lower(expiration),_uniffiStatus)
	}))
}




func (_self *Transaction) Expiration() *TransactionExpiration {
	_pointer := _self.ffiObject.incrementPointer("*Transaction")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterTransactionExpirationINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_transaction_expiration(
		_pointer,_uniffiStatus)
	}))
}

func (_self *Transaction) GasPayment() GasPayment {
	_pointer := _self.ffiObject.incrementPointer("*Transaction")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterGasPaymentINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_transaction_gas_payment(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *Transaction) Kind() *TransactionKind {
	_pointer := _self.ffiObject.incrementPointer("*Transaction")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_transaction_kind(
		_pointer,_uniffiStatus)
	}))
}

func (_self *Transaction) Sender() *Address {
	_pointer := _self.ffiObject.incrementPointer("*Transaction")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterAddressINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_transaction_sender(
		_pointer,_uniffiStatus)
	}))
}
func (object *Transaction) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransaction struct {}

var FfiConverterTransactionINSTANCE = FfiConverterTransaction{}


func (c FfiConverterTransaction) Lift(pointer unsafe.Pointer) *Transaction {
	result := &Transaction {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transaction(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transaction(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Transaction).Destroy)
	return result
}

func (c FfiConverterTransaction) Read(reader io.Reader) *Transaction {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransaction) Lower(value *Transaction) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Transaction")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransaction) Write(writer io.Writer, value *Transaction) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransaction struct {}

func (_ FfiDestroyerTransaction) Destroy(value *Transaction) {
		value.Destroy()
}



type TransactionDataEffectsInterface interface {
	Effects() *TransactionEffects
	Tx() *SignedTransaction
}
type TransactionDataEffects struct {
	ffiObject FfiObject
}
func NewTransactionDataEffects(tx *SignedTransaction, effects *TransactionEffects) *TransactionDataEffects {
	return FfiConverterTransactionDataEffectsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_transactiondataeffects_new(FfiConverterSignedTransactionINSTANCE.Lower(tx), FfiConverterTransactionEffectsINSTANCE.Lower(effects),_uniffiStatus)
	}))
}




func (_self *TransactionDataEffects) Effects() *TransactionEffects {
	_pointer := _self.ffiObject.incrementPointer("*TransactionDataEffects")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterTransactionEffectsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_transactiondataeffects_effects(
		_pointer,_uniffiStatus)
	}))
}

func (_self *TransactionDataEffects) Tx() *SignedTransaction {
	_pointer := _self.ffiObject.incrementPointer("*TransactionDataEffects")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSignedTransactionINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_transactiondataeffects_tx(
		_pointer,_uniffiStatus)
	}))
}
func (object *TransactionDataEffects) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionDataEffects struct {}

var FfiConverterTransactionDataEffectsINSTANCE = FfiConverterTransactionDataEffects{}


func (c FfiConverterTransactionDataEffects) Lift(pointer unsafe.Pointer) *TransactionDataEffects {
	result := &TransactionDataEffects {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactiondataeffects(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactiondataeffects(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionDataEffects).Destroy)
	return result
}

func (c FfiConverterTransactionDataEffects) Read(reader io.Reader) *TransactionDataEffects {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionDataEffects) Lower(value *TransactionDataEffects) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionDataEffects")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionDataEffects) Write(writer io.Writer, value *TransactionDataEffects) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionDataEffects struct {}

func (_ FfiDestroyerTransactionDataEffects) Destroy(value *TransactionDataEffects) {
		value.Destroy()
}



type TransactionDataEffectsPageInterface interface {
	Data() []*TransactionDataEffects
	IsEmpty() bool
	PageInfo() *PageInfo
}
type TransactionDataEffectsPage struct {
	ffiObject FfiObject
}




func (_self *TransactionDataEffectsPage) Data() []*TransactionDataEffects {
	_pointer := _self.ffiObject.incrementPointer("*TransactionDataEffectsPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceTransactionDataEffectsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_transactiondataeffectspage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *TransactionDataEffectsPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*TransactionDataEffectsPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_transactiondataeffectspage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *TransactionDataEffectsPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*TransactionDataEffectsPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_transactiondataeffectspage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *TransactionDataEffectsPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionDataEffectsPage struct {}

var FfiConverterTransactionDataEffectsPageINSTANCE = FfiConverterTransactionDataEffectsPage{}


func (c FfiConverterTransactionDataEffectsPage) Lift(pointer unsafe.Pointer) *TransactionDataEffectsPage {
	result := &TransactionDataEffectsPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactiondataeffectspage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactiondataeffectspage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionDataEffectsPage).Destroy)
	return result
}

func (c FfiConverterTransactionDataEffectsPage) Read(reader io.Reader) *TransactionDataEffectsPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionDataEffectsPage) Lower(value *TransactionDataEffectsPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionDataEffectsPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionDataEffectsPage) Write(writer io.Writer, value *TransactionDataEffectsPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionDataEffectsPage struct {}

func (_ FfiDestroyerTransactionDataEffectsPage) Destroy(value *TransactionDataEffectsPage) {
		value.Destroy()
}



type TransactionDigestInterface interface {
}
type TransactionDigest struct {
	ffiObject FfiObject
}



func (object *TransactionDigest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionDigest struct {}

var FfiConverterTransactionDigestINSTANCE = FfiConverterTransactionDigest{}


func (c FfiConverterTransactionDigest) Lift(pointer unsafe.Pointer) *TransactionDigest {
	result := &TransactionDigest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactiondigest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactiondigest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionDigest).Destroy)
	return result
}

func (c FfiConverterTransactionDigest) Read(reader io.Reader) *TransactionDigest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionDigest) Lower(value *TransactionDigest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionDigest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionDigest) Write(writer io.Writer, value *TransactionDigest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionDigest struct {}

func (_ FfiDestroyerTransactionDigest) Destroy(value *TransactionDigest) {
		value.Destroy()
}



type TransactionEffectsInterface interface {
}
type TransactionEffects struct {
	ffiObject FfiObject
}



func (object *TransactionEffects) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionEffects struct {}

var FfiConverterTransactionEffectsINSTANCE = FfiConverterTransactionEffects{}


func (c FfiConverterTransactionEffects) Lift(pointer unsafe.Pointer) *TransactionEffects {
	result := &TransactionEffects {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactioneffects(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactioneffects(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionEffects).Destroy)
	return result
}

func (c FfiConverterTransactionEffects) Read(reader io.Reader) *TransactionEffects {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionEffects) Lower(value *TransactionEffects) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionEffects")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionEffects) Write(writer io.Writer, value *TransactionEffects) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionEffects struct {}

func (_ FfiDestroyerTransactionEffects) Destroy(value *TransactionEffects) {
		value.Destroy()
}



type TransactionEffectsDigestInterface interface {
}
type TransactionEffectsDigest struct {
	ffiObject FfiObject
}



func (object *TransactionEffectsDigest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionEffectsDigest struct {}

var FfiConverterTransactionEffectsDigestINSTANCE = FfiConverterTransactionEffectsDigest{}


func (c FfiConverterTransactionEffectsDigest) Lift(pointer unsafe.Pointer) *TransactionEffectsDigest {
	result := &TransactionEffectsDigest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactioneffectsdigest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactioneffectsdigest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionEffectsDigest).Destroy)
	return result
}

func (c FfiConverterTransactionEffectsDigest) Read(reader io.Reader) *TransactionEffectsDigest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionEffectsDigest) Lower(value *TransactionEffectsDigest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionEffectsDigest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionEffectsDigest) Write(writer io.Writer, value *TransactionEffectsDigest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionEffectsDigest struct {}

func (_ FfiDestroyerTransactionEffectsDigest) Destroy(value *TransactionEffectsDigest) {
		value.Destroy()
}



type TransactionEffectsPageInterface interface {
	Data() []*TransactionEffects
	IsEmpty() bool
	PageInfo() *PageInfo
}
type TransactionEffectsPage struct {
	ffiObject FfiObject
}




func (_self *TransactionEffectsPage) Data() []*TransactionEffects {
	_pointer := _self.ffiObject.incrementPointer("*TransactionEffectsPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceTransactionEffectsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_transactioneffectspage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *TransactionEffectsPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*TransactionEffectsPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_transactioneffectspage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *TransactionEffectsPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*TransactionEffectsPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_transactioneffectspage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *TransactionEffectsPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionEffectsPage struct {}

var FfiConverterTransactionEffectsPageINSTANCE = FfiConverterTransactionEffectsPage{}


func (c FfiConverterTransactionEffectsPage) Lift(pointer unsafe.Pointer) *TransactionEffectsPage {
	result := &TransactionEffectsPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactioneffectspage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactioneffectspage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionEffectsPage).Destroy)
	return result
}

func (c FfiConverterTransactionEffectsPage) Read(reader io.Reader) *TransactionEffectsPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionEffectsPage) Lower(value *TransactionEffectsPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionEffectsPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionEffectsPage) Write(writer io.Writer, value *TransactionEffectsPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionEffectsPage struct {}

func (_ FfiDestroyerTransactionEffectsPage) Destroy(value *TransactionEffectsPage) {
		value.Destroy()
}



type TransactionEventsDigestInterface interface {
}
type TransactionEventsDigest struct {
	ffiObject FfiObject
}



func (object *TransactionEventsDigest) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionEventsDigest struct {}

var FfiConverterTransactionEventsDigestINSTANCE = FfiConverterTransactionEventsDigest{}


func (c FfiConverterTransactionEventsDigest) Lift(pointer unsafe.Pointer) *TransactionEventsDigest {
	result := &TransactionEventsDigest {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactioneventsdigest(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactioneventsdigest(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionEventsDigest).Destroy)
	return result
}

func (c FfiConverterTransactionEventsDigest) Read(reader io.Reader) *TransactionEventsDigest {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionEventsDigest) Lower(value *TransactionEventsDigest) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionEventsDigest")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionEventsDigest) Write(writer io.Writer, value *TransactionEventsDigest) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionEventsDigest struct {}

func (_ FfiDestroyerTransactionEventsDigest) Destroy(value *TransactionEventsDigest) {
		value.Destroy()
}



type TransactionExpirationInterface interface {
}
type TransactionExpiration struct {
	ffiObject FfiObject
}



func (object *TransactionExpiration) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionExpiration struct {}

var FfiConverterTransactionExpirationINSTANCE = FfiConverterTransactionExpiration{}


func (c FfiConverterTransactionExpiration) Lift(pointer unsafe.Pointer) *TransactionExpiration {
	result := &TransactionExpiration {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactionexpiration(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactionexpiration(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionExpiration).Destroy)
	return result
}

func (c FfiConverterTransactionExpiration) Read(reader io.Reader) *TransactionExpiration {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionExpiration) Lower(value *TransactionExpiration) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionExpiration")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionExpiration) Write(writer io.Writer, value *TransactionExpiration) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionExpiration struct {}

func (_ FfiDestroyerTransactionExpiration) Destroy(value *TransactionExpiration) {
		value.Destroy()
}



// Transaction type
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// transaction-kind    =  %x00 ptb
// =/ %x01 change-epoch
// =/ %x02 genesis-transaction
// =/ %x03 consensus-commit-prologue
// =/ %x04 authenticator-state-update
// =/ %x05 (vector end-of-epoch-transaction-kind)
// =/ %x06 randomness-state-update
// =/ %x07 consensus-commit-prologue-v2
// =/ %x08 consensus-commit-prologue-v3
// ```
type TransactionKindInterface interface {
}
// Transaction type
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// transaction-kind    =  %x00 ptb
// =/ %x01 change-epoch
// =/ %x02 genesis-transaction
// =/ %x03 consensus-commit-prologue
// =/ %x04 authenticator-state-update
// =/ %x05 (vector end-of-epoch-transaction-kind)
// =/ %x06 randomness-state-update
// =/ %x07 consensus-commit-prologue-v2
// =/ %x08 consensus-commit-prologue-v3
// ```
type TransactionKind struct {
	ffiObject FfiObject
}


func TransactionKindAuthenticatorStateUpdateV1(tx *AuthenticatorStateUpdateV1) *TransactionKind {
	return FfiConverterTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_transactionkind_authenticator_state_update_v1(FfiConverterAuthenticatorStateUpdateV1INSTANCE.Lower(tx),_uniffiStatus)
	}))
}

func TransactionKindConsensusCommitPrologueV1(tx *ConsensusCommitPrologueV1) *TransactionKind {
	return FfiConverterTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_transactionkind_consensus_commit_prologue_v1(FfiConverterConsensusCommitPrologueV1INSTANCE.Lower(tx),_uniffiStatus)
	}))
}

func TransactionKindEndOfEpoch(tx []*EndOfEpochTransactionKind) *TransactionKind {
	return FfiConverterTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_transactionkind_end_of_epoch(FfiConverterSequenceEndOfEpochTransactionKindINSTANCE.Lower(tx),_uniffiStatus)
	}))
}

func TransactionKindGenesis(tx *GenesisTransaction) *TransactionKind {
	return FfiConverterTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_transactionkind_genesis(FfiConverterGenesisTransactionINSTANCE.Lower(tx),_uniffiStatus)
	}))
}

func TransactionKindProgrammableTransaction(tx *ProgrammableTransaction) *TransactionKind {
	return FfiConverterTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_transactionkind_programmable_transaction(FfiConverterProgrammableTransactionINSTANCE.Lower(tx),_uniffiStatus)
	}))
}

func TransactionKindRandomnessStateUpdate(tx *RandomnessStateUpdate) *TransactionKind {
	return FfiConverterTransactionKindINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_constructor_transactionkind_randomness_state_update(FfiConverterRandomnessStateUpdateINSTANCE.Lower(tx),_uniffiStatus)
	}))
}


func (object *TransactionKind) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransactionKind struct {}

var FfiConverterTransactionKindINSTANCE = FfiConverterTransactionKind{}


func (c FfiConverterTransactionKind) Lift(pointer unsafe.Pointer) *TransactionKind {
	result := &TransactionKind {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_transactionkind(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_transactionkind(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransactionKind).Destroy)
	return result
}

func (c FfiConverterTransactionKind) Read(reader io.Reader) *TransactionKind {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTransactionKind) Lower(value *TransactionKind) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TransactionKind")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTransactionKind) Write(writer io.Writer, value *TransactionKind) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTransactionKind struct {}

func (_ FfiDestroyerTransactionKind) Destroy(value *TransactionKind) {
		value.Destroy()
}



type TypeTagInterface interface {
}
type TypeTag struct {
	ffiObject FfiObject
}



func (object *TypeTag) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTypeTag struct {}

var FfiConverterTypeTagINSTANCE = FfiConverterTypeTag{}


func (c FfiConverterTypeTag) Lift(pointer unsafe.Pointer) *TypeTag {
	result := &TypeTag {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_typetag(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_typetag(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TypeTag).Destroy)
	return result
}

func (c FfiConverterTypeTag) Read(reader io.Reader) *TypeTag {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterTypeTag) Lower(value *TypeTag) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*TypeTag")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterTypeTag) Write(writer io.Writer, value *TypeTag) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerTypeTag struct {}

func (_ FfiDestroyerTypeTag) Destroy(value *TypeTag) {
		value.Destroy()
}



type UserSignatureInterface interface {
}
type UserSignature struct {
	ffiObject FfiObject
}



func (object *UserSignature) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterUserSignature struct {}

var FfiConverterUserSignatureINSTANCE = FfiConverterUserSignature{}


func (c FfiConverterUserSignature) Lift(pointer unsafe.Pointer) *UserSignature {
	result := &UserSignature {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_usersignature(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_usersignature(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*UserSignature).Destroy)
	return result
}

func (c FfiConverterUserSignature) Read(reader io.Reader) *UserSignature {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterUserSignature) Lower(value *UserSignature) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*UserSignature")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterUserSignature) Write(writer io.Writer, value *UserSignature) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerUserSignature struct {}

func (_ FfiDestroyerUserSignature) Destroy(value *UserSignature) {
		value.Destroy()
}



type ValidatorInterface interface {
}
type Validator struct {
	ffiObject FfiObject
}



func (object *Validator) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterValidator struct {}

var FfiConverterValidatorINSTANCE = FfiConverterValidator{}


func (c FfiConverterValidator) Lift(pointer unsafe.Pointer) *Validator {
	result := &Validator {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_validator(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_validator(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Validator).Destroy)
	return result
}

func (c FfiConverterValidator) Read(reader io.Reader) *Validator {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterValidator) Lower(value *Validator) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Validator")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterValidator) Write(writer io.Writer, value *Validator) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerValidator struct {}

func (_ FfiDestroyerValidator) Destroy(value *Validator) {
		value.Destroy()
}



type ValidatorPageInterface interface {
	Data() []*Validator
	IsEmpty() bool
	PageInfo() *PageInfo
}
type ValidatorPage struct {
	ffiObject FfiObject
}




func (_self *ValidatorPage) Data() []*Validator {
	_pointer := _self.ffiObject.incrementPointer("*ValidatorPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceValidatorINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_iota_sdk_ffi_fn_method_validatorpage_data(
		_pointer,_uniffiStatus),
	}
	}))
}

func (_self *ValidatorPage) IsEmpty() bool {
	_pointer := _self.ffiObject.incrementPointer("*ValidatorPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_iota_sdk_ffi_fn_method_validatorpage_is_empty(
		_pointer,_uniffiStatus)
	}))
}

func (_self *ValidatorPage) PageInfo() *PageInfo {
	_pointer := _self.ffiObject.incrementPointer("*ValidatorPage")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterPageInfoINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_iota_sdk_ffi_fn_method_validatorpage_page_info(
		_pointer,_uniffiStatus)
	}))
}
func (object *ValidatorPage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterValidatorPage struct {}

var FfiConverterValidatorPageINSTANCE = FfiConverterValidatorPage{}


func (c FfiConverterValidatorPage) Lift(pointer unsafe.Pointer) *ValidatorPage {
	result := &ValidatorPage {
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_iota_sdk_ffi_fn_clone_validatorpage(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_iota_sdk_ffi_fn_free_validatorpage(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*ValidatorPage).Destroy)
	return result
}

func (c FfiConverterValidatorPage) Read(reader io.Reader) *ValidatorPage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterValidatorPage) Lower(value *ValidatorPage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*ValidatorPage")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c FfiConverterValidatorPage) Write(writer io.Writer, value *ValidatorPage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerValidatorPage struct {}

func (_ FfiDestroyerValidatorPage) Destroy(value *ValidatorPage) {
		value.Destroy()
}



// A header for a Checkpoint on the IOTA blockchain.
//
// On the IOTA network, checkpoints define the history of the blockchain. They
// are quite similar to the concept of blocks used by other blockchains like
// Bitcoin or Ethereum. The IOTA blockchain, however, forms checkpoints after
// transaction execution has already happened to provide a certified history of
// the chain, instead of being formed before execution.
//
// Checkpoints commit to a variety of state including but not limited to:
// - The hash of the previous checkpoint.
// - The set of transaction digests, their corresponding effects digests, as
// well as the set of user signatures which authorized its execution.
// - The object's produced by a transaction.
// - The set of live objects that make up the current state of the chain.
// - On epoch transitions, the next validator committee.
//
// `CheckpointSummary`s themselves don't directly include all of the above
// information but they are the top-level type by which all the above are
// committed to transitively via cryptographic hashes included in the summary.
// `CheckpointSummary`s are signed and certified by a quorum of the validator
// committee in a given epoch in order to allow verification of the chain's
// state.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// checkpoint-summary = u64                            ; epoch
// u64                            ; sequence_number
// u64                            ; network_total_transactions
// digest                         ; content_digest
// (option digest)                ; previous_digest
// gas-cost-summary               ; epoch_rolling_gas_cost_summary
// u64                            ; timestamp_ms
// (vector checkpoint-commitment) ; checkpoint_commitments
// (option end-of-epoch-data)     ; end_of_epoch_data
// bytes                          ; version_specific_data
// ```
type CheckpointSummary struct {
	// Epoch that this checkpoint belongs to.
	Epoch uint64
	// The height of this checkpoint.
	SequenceNumber uint64
	// Total number of transactions committed since genesis, including those in
	// this checkpoint.
	NetworkTotalTransactions uint64
	// The hash of the `CheckpointContents` for this checkpoint.
	ContentDigest *CheckpointContentsDigest
	// The hash of the previous `CheckpointSummary`.
	//
	// This will be only be `None` for the first, or genesis checkpoint.
	PreviousDigest **CheckpointDigest
	// The running total gas costs of all transactions included in the current
	// epoch so far until this checkpoint.
	EpochRollingGasCostSummary GasCostSummary
	// Timestamp of the checkpoint - number of milliseconds from the Unix epoch
	// Checkpoint timestamps are monotonic, but not strongly monotonic -
	// subsequent checkpoints can have same timestamp if they originate
	// from the same underlining consensus commit
	TimestampMs uint64
	// Commitments to checkpoint-specific state.
	CheckpointCommitments []*CheckpointCommitment
	// Extra data only present in the final checkpoint of an epoch.
	EndOfEpochData *EndOfEpochData
	// CheckpointSummary is not an evolvable structure - it must be readable by
	// any version of the code. Therefore, in order to allow extensions to
	// be added to CheckpointSummary, we allow opaque data to be added to
	// checkpoints which can be deserialized based on the current
	// protocol version.
	VersionSpecificData []byte
}

func (r *CheckpointSummary) Destroy() {
		FfiDestroyerUint64{}.Destroy(r.Epoch);
		FfiDestroyerUint64{}.Destroy(r.SequenceNumber);
		FfiDestroyerUint64{}.Destroy(r.NetworkTotalTransactions);
		FfiDestroyerCheckpointContentsDigest{}.Destroy(r.ContentDigest);
		FfiDestroyerOptionalCheckpointDigest{}.Destroy(r.PreviousDigest);
		FfiDestroyerGasCostSummary{}.Destroy(r.EpochRollingGasCostSummary);
		FfiDestroyerUint64{}.Destroy(r.TimestampMs);
		FfiDestroyerSequenceCheckpointCommitment{}.Destroy(r.CheckpointCommitments);
		FfiDestroyerOptionalEndOfEpochData{}.Destroy(r.EndOfEpochData);
		FfiDestroyerBytes{}.Destroy(r.VersionSpecificData);
}

type FfiConverterCheckpointSummary struct {}

var FfiConverterCheckpointSummaryINSTANCE = FfiConverterCheckpointSummary{}

func (c FfiConverterCheckpointSummary) Lift(rb RustBufferI) CheckpointSummary {
	return LiftFromRustBuffer[CheckpointSummary](c, rb)
}

func (c FfiConverterCheckpointSummary) Read(reader io.Reader) CheckpointSummary {
	return CheckpointSummary {
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterCheckpointContentsDigestINSTANCE.Read(reader),
			FfiConverterOptionalCheckpointDigestINSTANCE.Read(reader),
			FfiConverterGasCostSummaryINSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterSequenceCheckpointCommitmentINSTANCE.Read(reader),
			FfiConverterOptionalEndOfEpochDataINSTANCE.Read(reader),
			FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterCheckpointSummary) Lower(value CheckpointSummary) C.RustBuffer {
	return LowerIntoRustBuffer[CheckpointSummary](c, value)
}

func (c FfiConverterCheckpointSummary) Write(writer io.Writer, value CheckpointSummary) {
		FfiConverterUint64INSTANCE.Write(writer, value.Epoch);
		FfiConverterUint64INSTANCE.Write(writer, value.SequenceNumber);
		FfiConverterUint64INSTANCE.Write(writer, value.NetworkTotalTransactions);
		FfiConverterCheckpointContentsDigestINSTANCE.Write(writer, value.ContentDigest);
		FfiConverterOptionalCheckpointDigestINSTANCE.Write(writer, value.PreviousDigest);
		FfiConverterGasCostSummaryINSTANCE.Write(writer, value.EpochRollingGasCostSummary);
		FfiConverterUint64INSTANCE.Write(writer, value.TimestampMs);
		FfiConverterSequenceCheckpointCommitmentINSTANCE.Write(writer, value.CheckpointCommitments);
		FfiConverterOptionalEndOfEpochDataINSTANCE.Write(writer, value.EndOfEpochData);
		FfiConverterBytesINSTANCE.Write(writer, value.VersionSpecificData);
}

type FfiDestroyerCheckpointSummary struct {}

func (_ FfiDestroyerCheckpointSummary) Destroy(value CheckpointSummary) {
	value.Destroy()
}
type EndOfEpochData struct {
	NextEpochCommittee []ValidatorCommitteeMember
	NextEpochProtocolVersion uint64
	EpochCommitments []*CheckpointCommitment
	EpochSupplyChange int64
}

func (r *EndOfEpochData) Destroy() {
		FfiDestroyerSequenceValidatorCommitteeMember{}.Destroy(r.NextEpochCommittee);
		FfiDestroyerUint64{}.Destroy(r.NextEpochProtocolVersion);
		FfiDestroyerSequenceCheckpointCommitment{}.Destroy(r.EpochCommitments);
		FfiDestroyerInt64{}.Destroy(r.EpochSupplyChange);
}

type FfiConverterEndOfEpochData struct {}

var FfiConverterEndOfEpochDataINSTANCE = FfiConverterEndOfEpochData{}

func (c FfiConverterEndOfEpochData) Lift(rb RustBufferI) EndOfEpochData {
	return LiftFromRustBuffer[EndOfEpochData](c, rb)
}

func (c FfiConverterEndOfEpochData) Read(reader io.Reader) EndOfEpochData {
	return EndOfEpochData {
			FfiConverterSequenceValidatorCommitteeMemberINSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterSequenceCheckpointCommitmentINSTANCE.Read(reader),
			FfiConverterInt64INSTANCE.Read(reader),
	}
}

func (c FfiConverterEndOfEpochData) Lower(value EndOfEpochData) C.RustBuffer {
	return LowerIntoRustBuffer[EndOfEpochData](c, value)
}

func (c FfiConverterEndOfEpochData) Write(writer io.Writer, value EndOfEpochData) {
		FfiConverterSequenceValidatorCommitteeMemberINSTANCE.Write(writer, value.NextEpochCommittee);
		FfiConverterUint64INSTANCE.Write(writer, value.NextEpochProtocolVersion);
		FfiConverterSequenceCheckpointCommitmentINSTANCE.Write(writer, value.EpochCommitments);
		FfiConverterInt64INSTANCE.Write(writer, value.EpochSupplyChange);
}

type FfiDestroyerEndOfEpochData struct {}

func (_ FfiDestroyerEndOfEpochData) Destroy(value EndOfEpochData) {
	value.Destroy()
}
type EventFilter struct {
	EmittingModule *string
	EventType *string
	Sender **Address
	TransactionDigest *string
}

func (r *EventFilter) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.EmittingModule);
		FfiDestroyerOptionalString{}.Destroy(r.EventType);
		FfiDestroyerOptionalAddress{}.Destroy(r.Sender);
		FfiDestroyerOptionalString{}.Destroy(r.TransactionDigest);
}

type FfiConverterEventFilter struct {}

var FfiConverterEventFilterINSTANCE = FfiConverterEventFilter{}

func (c FfiConverterEventFilter) Lift(rb RustBufferI) EventFilter {
	return LiftFromRustBuffer[EventFilter](c, rb)
}

func (c FfiConverterEventFilter) Read(reader io.Reader) EventFilter {
	return EventFilter {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalAddressINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterEventFilter) Lower(value EventFilter) C.RustBuffer {
	return LowerIntoRustBuffer[EventFilter](c, value)
}

func (c FfiConverterEventFilter) Write(writer io.Writer, value EventFilter) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.EmittingModule);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.EventType);
		FfiConverterOptionalAddressINSTANCE.Write(writer, value.Sender);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.TransactionDigest);
}

type FfiDestroyerEventFilter struct {}

func (_ FfiDestroyerEventFilter) Destroy(value EventFilter) {
	value.Destroy()
}
type GasCostSummary struct {
	ComputationCost uint64
	ComputationCostBurned uint64
	StorageCost uint64
	StorageRebate uint64
	NonRefundableStorageFee uint64
}

func (r *GasCostSummary) Destroy() {
		FfiDestroyerUint64{}.Destroy(r.ComputationCost);
		FfiDestroyerUint64{}.Destroy(r.ComputationCostBurned);
		FfiDestroyerUint64{}.Destroy(r.StorageCost);
		FfiDestroyerUint64{}.Destroy(r.StorageRebate);
		FfiDestroyerUint64{}.Destroy(r.NonRefundableStorageFee);
}

type FfiConverterGasCostSummary struct {}

var FfiConverterGasCostSummaryINSTANCE = FfiConverterGasCostSummary{}

func (c FfiConverterGasCostSummary) Lift(rb RustBufferI) GasCostSummary {
	return LiftFromRustBuffer[GasCostSummary](c, rb)
}

func (c FfiConverterGasCostSummary) Read(reader io.Reader) GasCostSummary {
	return GasCostSummary {
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterGasCostSummary) Lower(value GasCostSummary) C.RustBuffer {
	return LowerIntoRustBuffer[GasCostSummary](c, value)
}

func (c FfiConverterGasCostSummary) Write(writer io.Writer, value GasCostSummary) {
		FfiConverterUint64INSTANCE.Write(writer, value.ComputationCost);
		FfiConverterUint64INSTANCE.Write(writer, value.ComputationCostBurned);
		FfiConverterUint64INSTANCE.Write(writer, value.StorageCost);
		FfiConverterUint64INSTANCE.Write(writer, value.StorageRebate);
		FfiConverterUint64INSTANCE.Write(writer, value.NonRefundableStorageFee);
}

type FfiDestroyerGasCostSummary struct {}

func (_ FfiDestroyerGasCostSummary) Destroy(value GasCostSummary) {
	value.Destroy()
}
// Payment information for executing a transaction
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// gas-payment = (vector object-ref) ; gas coin objects
// address             ; owner
// u64                 ; price
// u64                 ; budget
// ```
type GasPayment struct {
	Objects []ObjectReference
	Owner *Address
	Price uint64
	Budget uint64
}

func (r *GasPayment) Destroy() {
		FfiDestroyerSequenceObjectReference{}.Destroy(r.Objects);
		FfiDestroyerAddress{}.Destroy(r.Owner);
		FfiDestroyerUint64{}.Destroy(r.Price);
		FfiDestroyerUint64{}.Destroy(r.Budget);
}

type FfiConverterGasPayment struct {}

var FfiConverterGasPaymentINSTANCE = FfiConverterGasPayment{}

func (c FfiConverterGasPayment) Lift(rb RustBufferI) GasPayment {
	return LiftFromRustBuffer[GasPayment](c, rb)
}

func (c FfiConverterGasPayment) Read(reader io.Reader) GasPayment {
	return GasPayment {
			FfiConverterSequenceObjectReferenceINSTANCE.Read(reader),
			FfiConverterAddressINSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterGasPayment) Lower(value GasPayment) C.RustBuffer {
	return LowerIntoRustBuffer[GasPayment](c, value)
}

func (c FfiConverterGasPayment) Write(writer io.Writer, value GasPayment) {
		FfiConverterSequenceObjectReferenceINSTANCE.Write(writer, value.Objects);
		FfiConverterAddressINSTANCE.Write(writer, value.Owner);
		FfiConverterUint64INSTANCE.Write(writer, value.Price);
		FfiConverterUint64INSTANCE.Write(writer, value.Budget);
}

type FfiDestroyerGasPayment struct {}

func (_ FfiDestroyerGasPayment) Destroy(value GasPayment) {
	value.Destroy()
}
// Reference to an object
//
// Contains sufficient information to uniquely identify a specific object.
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// object-ref = object-id u64 digest
// ```
type ObjectReference struct {
	ObjectId *ObjectId
	Version uint64
	Digest *ObjectDigest
}

func (r *ObjectReference) Destroy() {
		FfiDestroyerObjectId{}.Destroy(r.ObjectId);
		FfiDestroyerUint64{}.Destroy(r.Version);
		FfiDestroyerObjectDigest{}.Destroy(r.Digest);
}

type FfiConverterObjectReference struct {}

var FfiConverterObjectReferenceINSTANCE = FfiConverterObjectReference{}

func (c FfiConverterObjectReference) Lift(rb RustBufferI) ObjectReference {
	return LiftFromRustBuffer[ObjectReference](c, rb)
}

func (c FfiConverterObjectReference) Read(reader io.Reader) ObjectReference {
	return ObjectReference {
			FfiConverterObjectIdINSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterObjectDigestINSTANCE.Read(reader),
	}
}

func (c FfiConverterObjectReference) Lower(value ObjectReference) C.RustBuffer {
	return LowerIntoRustBuffer[ObjectReference](c, value)
}

func (c FfiConverterObjectReference) Write(writer io.Writer, value ObjectReference) {
		FfiConverterObjectIdINSTANCE.Write(writer, value.ObjectId);
		FfiConverterUint64INSTANCE.Write(writer, value.Version);
		FfiConverterObjectDigestINSTANCE.Write(writer, value.Digest);
}

type FfiDestroyerObjectReference struct {}

func (_ FfiDestroyerObjectReference) Destroy(value ObjectReference) {
	value.Destroy()
}
// Pagination options for querying the GraphQL server. It defaults to forward
// pagination with the GraphQL server's max page size.
type PaginationFilter struct {
	// The direction of pagination.
	Direction Direction
	// An opaque cursor used for pagination.
	Cursor *string
	// The maximum number of items to return. If this is ommitted, it will
	// lazily query the service configuration for the max page size.
	Limit *int32
}

func (r *PaginationFilter) Destroy() {
		FfiDestroyerDirection{}.Destroy(r.Direction);
		FfiDestroyerOptionalString{}.Destroy(r.Cursor);
		FfiDestroyerOptionalInt32{}.Destroy(r.Limit);
}

type FfiConverterPaginationFilter struct {}

var FfiConverterPaginationFilterINSTANCE = FfiConverterPaginationFilter{}

func (c FfiConverterPaginationFilter) Lift(rb RustBufferI) PaginationFilter {
	return LiftFromRustBuffer[PaginationFilter](c, rb)
}

func (c FfiConverterPaginationFilter) Read(reader io.Reader) PaginationFilter {
	return PaginationFilter {
			FfiConverterDirectionINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalInt32INSTANCE.Read(reader),
	}
}

func (c FfiConverterPaginationFilter) Lower(value PaginationFilter) C.RustBuffer {
	return LowerIntoRustBuffer[PaginationFilter](c, value)
}

func (c FfiConverterPaginationFilter) Write(writer io.Writer, value PaginationFilter) {
		FfiConverterDirectionINSTANCE.Write(writer, value.Direction);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Cursor);
		FfiConverterOptionalInt32INSTANCE.Write(writer, value.Limit);
}

type FfiDestroyerPaginationFilter struct {}

func (_ FfiDestroyerPaginationFilter) Destroy(value PaginationFilter) {
	value.Destroy()
}
type TransactionMetadata struct {
	GasBudget *uint64
	GasObjects *[]*ObjectRef
	GasPrice *uint64
	GasSponsor **Address
	Sender **Address
}

func (r *TransactionMetadata) Destroy() {
		FfiDestroyerOptionalUint64{}.Destroy(r.GasBudget);
		FfiDestroyerOptionalSequenceObjectRef{}.Destroy(r.GasObjects);
		FfiDestroyerOptionalUint64{}.Destroy(r.GasPrice);
		FfiDestroyerOptionalAddress{}.Destroy(r.GasSponsor);
		FfiDestroyerOptionalAddress{}.Destroy(r.Sender);
}

type FfiConverterTransactionMetadata struct {}

var FfiConverterTransactionMetadataINSTANCE = FfiConverterTransactionMetadata{}

func (c FfiConverterTransactionMetadata) Lift(rb RustBufferI) TransactionMetadata {
	return LiftFromRustBuffer[TransactionMetadata](c, rb)
}

func (c FfiConverterTransactionMetadata) Read(reader io.Reader) TransactionMetadata {
	return TransactionMetadata {
			FfiConverterOptionalUint64INSTANCE.Read(reader),
			FfiConverterOptionalSequenceObjectRefINSTANCE.Read(reader),
			FfiConverterOptionalUint64INSTANCE.Read(reader),
			FfiConverterOptionalAddressINSTANCE.Read(reader),
			FfiConverterOptionalAddressINSTANCE.Read(reader),
	}
}

func (c FfiConverterTransactionMetadata) Lower(value TransactionMetadata) C.RustBuffer {
	return LowerIntoRustBuffer[TransactionMetadata](c, value)
}

func (c FfiConverterTransactionMetadata) Write(writer io.Writer, value TransactionMetadata) {
		FfiConverterOptionalUint64INSTANCE.Write(writer, value.GasBudget);
		FfiConverterOptionalSequenceObjectRefINSTANCE.Write(writer, value.GasObjects);
		FfiConverterOptionalUint64INSTANCE.Write(writer, value.GasPrice);
		FfiConverterOptionalAddressINSTANCE.Write(writer, value.GasSponsor);
		FfiConverterOptionalAddressINSTANCE.Write(writer, value.Sender);
}

type FfiDestroyerTransactionMetadata struct {}

func (_ FfiDestroyerTransactionMetadata) Destroy(value TransactionMetadata) {
	value.Destroy()
}
type TransactionsFilter struct {
	Function *string
	Kind *TransactionBlockKindInput
	AfterCheckpoint *uint64
	AtCheckpoint *uint64
	BeforeCheckpoint *uint64
	SignAddress **Address
	RecvAddress **Address
	InputObject **ObjectId
	ChangedObject **ObjectId
	TransactionIds *[]string
	WrappedOrDeletedObject **ObjectId
}

func (r *TransactionsFilter) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Function);
		FfiDestroyerOptionalTransactionBlockKindInput{}.Destroy(r.Kind);
		FfiDestroyerOptionalUint64{}.Destroy(r.AfterCheckpoint);
		FfiDestroyerOptionalUint64{}.Destroy(r.AtCheckpoint);
		FfiDestroyerOptionalUint64{}.Destroy(r.BeforeCheckpoint);
		FfiDestroyerOptionalAddress{}.Destroy(r.SignAddress);
		FfiDestroyerOptionalAddress{}.Destroy(r.RecvAddress);
		FfiDestroyerOptionalObjectId{}.Destroy(r.InputObject);
		FfiDestroyerOptionalObjectId{}.Destroy(r.ChangedObject);
		FfiDestroyerOptionalSequenceString{}.Destroy(r.TransactionIds);
		FfiDestroyerOptionalObjectId{}.Destroy(r.WrappedOrDeletedObject);
}

type FfiConverterTransactionsFilter struct {}

var FfiConverterTransactionsFilterINSTANCE = FfiConverterTransactionsFilter{}

func (c FfiConverterTransactionsFilter) Lift(rb RustBufferI) TransactionsFilter {
	return LiftFromRustBuffer[TransactionsFilter](c, rb)
}

func (c FfiConverterTransactionsFilter) Read(reader io.Reader) TransactionsFilter {
	return TransactionsFilter {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalTransactionBlockKindInputINSTANCE.Read(reader),
			FfiConverterOptionalUint64INSTANCE.Read(reader),
			FfiConverterOptionalUint64INSTANCE.Read(reader),
			FfiConverterOptionalUint64INSTANCE.Read(reader),
			FfiConverterOptionalAddressINSTANCE.Read(reader),
			FfiConverterOptionalAddressINSTANCE.Read(reader),
			FfiConverterOptionalObjectIdINSTANCE.Read(reader),
			FfiConverterOptionalObjectIdINSTANCE.Read(reader),
			FfiConverterOptionalSequenceStringINSTANCE.Read(reader),
			FfiConverterOptionalObjectIdINSTANCE.Read(reader),
	}
}

func (c FfiConverterTransactionsFilter) Lower(value TransactionsFilter) C.RustBuffer {
	return LowerIntoRustBuffer[TransactionsFilter](c, value)
}

func (c FfiConverterTransactionsFilter) Write(writer io.Writer, value TransactionsFilter) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Function);
		FfiConverterOptionalTransactionBlockKindInputINSTANCE.Write(writer, value.Kind);
		FfiConverterOptionalUint64INSTANCE.Write(writer, value.AfterCheckpoint);
		FfiConverterOptionalUint64INSTANCE.Write(writer, value.AtCheckpoint);
		FfiConverterOptionalUint64INSTANCE.Write(writer, value.BeforeCheckpoint);
		FfiConverterOptionalAddressINSTANCE.Write(writer, value.SignAddress);
		FfiConverterOptionalAddressINSTANCE.Write(writer, value.RecvAddress);
		FfiConverterOptionalObjectIdINSTANCE.Write(writer, value.InputObject);
		FfiConverterOptionalObjectIdINSTANCE.Write(writer, value.ChangedObject);
		FfiConverterOptionalSequenceStringINSTANCE.Write(writer, value.TransactionIds);
		FfiConverterOptionalObjectIdINSTANCE.Write(writer, value.WrappedOrDeletedObject);
}

type FfiDestroyerTransactionsFilter struct {}

func (_ FfiDestroyerTransactionsFilter) Destroy(value TransactionsFilter) {
	value.Destroy()
}
// A member of a Validator Committee
//
// # BCS
//
// The BCS serialized form for this type is defined by the following ABNF:
//
// ```text
// validator-committee-member = bls-public-key
// u64 ; stake
// ```
type ValidatorCommitteeMember struct {
	PublicKey *Bls12381PublicKey
	Stake uint64
}

func (r *ValidatorCommitteeMember) Destroy() {
		FfiDestroyerBls12381PublicKey{}.Destroy(r.PublicKey);
		FfiDestroyerUint64{}.Destroy(r.Stake);
}

type FfiConverterValidatorCommitteeMember struct {}

var FfiConverterValidatorCommitteeMemberINSTANCE = FfiConverterValidatorCommitteeMember{}

func (c FfiConverterValidatorCommitteeMember) Lift(rb RustBufferI) ValidatorCommitteeMember {
	return LiftFromRustBuffer[ValidatorCommitteeMember](c, rb)
}

func (c FfiConverterValidatorCommitteeMember) Read(reader io.Reader) ValidatorCommitteeMember {
	return ValidatorCommitteeMember {
			FfiConverterBls12381PublicKeyINSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterValidatorCommitteeMember) Lower(value ValidatorCommitteeMember) C.RustBuffer {
	return LowerIntoRustBuffer[ValidatorCommitteeMember](c, value)
}

func (c FfiConverterValidatorCommitteeMember) Write(writer io.Writer, value ValidatorCommitteeMember) {
		FfiConverterBls12381PublicKeyINSTANCE.Write(writer, value.PublicKey);
		FfiConverterUint64INSTANCE.Write(writer, value.Stake);
}

type FfiDestroyerValidatorCommitteeMember struct {}

func (_ FfiDestroyerValidatorCommitteeMember) Destroy(value ValidatorCommitteeMember) {
	value.Destroy()
}


// Pagination direction.
type Direction uint

const (
	DirectionForward Direction = 1
	DirectionBackward Direction = 2
)

type FfiConverterDirection struct {}

var FfiConverterDirectionINSTANCE = FfiConverterDirection{}

func (c FfiConverterDirection) Lift(rb RustBufferI) Direction {
	return LiftFromRustBuffer[Direction](c, rb)
}

func (c FfiConverterDirection) Lower(value Direction) C.RustBuffer {
	return LowerIntoRustBuffer[Direction](c, value)
}
func (FfiConverterDirection) Read(reader io.Reader) Direction {
	id := readInt32(reader)
	return Direction(id)
}

func (FfiConverterDirection) Write(writer io.Writer, value Direction) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerDirection struct {}

func (_ FfiDestroyerDirection) Destroy(value Direction) {
}
type SdkFfiError struct {
	err error
}

// Convience method to turn *SdkFfiError into error
// Avoiding treating nil pointer as non nil error interface
func (err *SdkFfiError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err SdkFfiError) Error() string {
	return fmt.Sprintf("SdkFfiError: %s", err.err.Error())
}

func (err SdkFfiError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrSdkFfiErrorGeneric = fmt.Errorf("SdkFfiErrorGeneric")

// Variant structs
type SdkFfiErrorGeneric struct {
	message string
}
func NewSdkFfiErrorGeneric(
) *SdkFfiError {
	return &SdkFfiError { err: &SdkFfiErrorGeneric {} }
}

func (e SdkFfiErrorGeneric) destroy() {
}


func (err SdkFfiErrorGeneric) Error() string {
	return fmt.Sprintf("Generic: %s", err.message)
}

func (self SdkFfiErrorGeneric) Is(target error) bool {
	return target == ErrSdkFfiErrorGeneric
}

type FfiConverterSdkFfiError struct{}

var FfiConverterSdkFfiErrorINSTANCE = FfiConverterSdkFfiError{}

func (c FfiConverterSdkFfiError) Lift(eb RustBufferI) *SdkFfiError {
	return LiftFromRustBuffer[*SdkFfiError](c, eb)
}

func (c FfiConverterSdkFfiError) Lower(value *SdkFfiError) C.RustBuffer {
	return LowerIntoRustBuffer[*SdkFfiError](c, value)
}

func (c FfiConverterSdkFfiError) Read(reader io.Reader) *SdkFfiError {
	errorID := readUint32(reader)

	message := FfiConverterStringINSTANCE.Read(reader)
	switch errorID {
	case 1:
		return &SdkFfiError{ &SdkFfiErrorGeneric{message}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterSdkFfiError.Read()", errorID))
	}

	
}

func (c FfiConverterSdkFfiError) Write(writer io.Writer, value *SdkFfiError) {
	switch variantValue := value.err.(type) {
		case *SdkFfiErrorGeneric:
			writeInt32(writer, 1)
		default:
			_ = variantValue
			panic(fmt.Sprintf("invalid error value `%v` in FfiConverterSdkFfiError.Write", value))
	}
}

type FfiDestroyerSdkFfiError struct {}

func (_ FfiDestroyerSdkFfiError) Destroy(value *SdkFfiError) {
	switch variantValue := value.err.(type) {
		case SdkFfiErrorGeneric:
			variantValue.destroy()
		default:
			_ = variantValue
			panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerSdkFfiError.Destroy", value))
	}
}



type TransactionBlockKindInput uint

const (
	TransactionBlockKindInputSystemTx TransactionBlockKindInput = 1
	TransactionBlockKindInputProgrammableTx TransactionBlockKindInput = 2
	TransactionBlockKindInputGenesis TransactionBlockKindInput = 3
	TransactionBlockKindInputConsensusCommitPrologueV1 TransactionBlockKindInput = 4
	TransactionBlockKindInputAuthenticatorStateUpdateV1 TransactionBlockKindInput = 5
	TransactionBlockKindInputRandomnessStateUpdate TransactionBlockKindInput = 6
	TransactionBlockKindInputEndOfEpochTx TransactionBlockKindInput = 7
)

type FfiConverterTransactionBlockKindInput struct {}

var FfiConverterTransactionBlockKindInputINSTANCE = FfiConverterTransactionBlockKindInput{}

func (c FfiConverterTransactionBlockKindInput) Lift(rb RustBufferI) TransactionBlockKindInput {
	return LiftFromRustBuffer[TransactionBlockKindInput](c, rb)
}

func (c FfiConverterTransactionBlockKindInput) Lower(value TransactionBlockKindInput) C.RustBuffer {
	return LowerIntoRustBuffer[TransactionBlockKindInput](c, value)
}
func (FfiConverterTransactionBlockKindInput) Read(reader io.Reader) TransactionBlockKindInput {
	id := readInt32(reader)
	return TransactionBlockKindInput(id)
}

func (FfiConverterTransactionBlockKindInput) Write(writer io.Writer, value TransactionBlockKindInput) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerTransactionBlockKindInput struct {}

func (_ FfiDestroyerTransactionBlockKindInput) Destroy(value TransactionBlockKindInput) {
}

type FfiConverterOptionalInt32 struct{}

var FfiConverterOptionalInt32INSTANCE = FfiConverterOptionalInt32{}

func (c FfiConverterOptionalInt32) Lift(rb RustBufferI) *int32 {
	return LiftFromRustBuffer[*int32](c, rb)
}

func (_ FfiConverterOptionalInt32) Read(reader io.Reader) *int32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterInt32INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalInt32) Lower(value *int32) C.RustBuffer {
	return LowerIntoRustBuffer[*int32](c, value)
}

func (_ FfiConverterOptionalInt32) Write(writer io.Writer, value *int32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterInt32INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalInt32 struct {}

func (_ FfiDestroyerOptionalInt32) Destroy(value *int32) {
	if value != nil {
		FfiDestroyerInt32{}.Destroy(*value)
	}
}

type FfiConverterOptionalUint64 struct{}

var FfiConverterOptionalUint64INSTANCE = FfiConverterOptionalUint64{}

func (c FfiConverterOptionalUint64) Lift(rb RustBufferI) *uint64 {
	return LiftFromRustBuffer[*uint64](c, rb)
}

func (_ FfiConverterOptionalUint64) Read(reader io.Reader) *uint64 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint64INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint64) Lower(value *uint64) C.RustBuffer {
	return LowerIntoRustBuffer[*uint64](c, value)
}

func (_ FfiConverterOptionalUint64) Write(writer io.Writer, value *uint64) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint64INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint64 struct {}

func (_ FfiDestroyerOptionalUint64) Destroy(value *uint64) {
	if value != nil {
		FfiDestroyerUint64{}.Destroy(*value)
	}
}

type FfiConverterOptionalBool struct{}

var FfiConverterOptionalBoolINSTANCE = FfiConverterOptionalBool{}

func (c FfiConverterOptionalBool) Lift(rb RustBufferI) *bool {
	return LiftFromRustBuffer[*bool](c, rb)
}

func (_ FfiConverterOptionalBool) Read(reader io.Reader) *bool {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterBoolINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalBool) Lower(value *bool) C.RustBuffer {
	return LowerIntoRustBuffer[*bool](c, value)
}

func (_ FfiConverterOptionalBool) Write(writer io.Writer, value *bool) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterBoolINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalBool struct {}

func (_ FfiDestroyerOptionalBool) Destroy(value *bool) {
	if value != nil {
		FfiDestroyerBool{}.Destroy(*value)
	}
}

type FfiConverterOptionalString struct{}

var FfiConverterOptionalStringINSTANCE = FfiConverterOptionalString{}

func (c FfiConverterOptionalString) Lift(rb RustBufferI) *string {
	return LiftFromRustBuffer[*string](c, rb)
}

func (_ FfiConverterOptionalString) Read(reader io.Reader) *string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalString) Lower(value *string) C.RustBuffer {
	return LowerIntoRustBuffer[*string](c, value)
}

func (_ FfiConverterOptionalString) Write(writer io.Writer, value *string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalString struct {}

func (_ FfiDestroyerOptionalString) Destroy(value *string) {
	if value != nil {
		FfiDestroyerString{}.Destroy(*value)
	}
}

type FfiConverterOptionalBytes struct{}

var FfiConverterOptionalBytesINSTANCE = FfiConverterOptionalBytes{}

func (c FfiConverterOptionalBytes) Lift(rb RustBufferI) *[]byte {
	return LiftFromRustBuffer[*[]byte](c, rb)
}

func (_ FfiConverterOptionalBytes) Read(reader io.Reader) *[]byte {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterBytesINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalBytes) Lower(value *[]byte) C.RustBuffer {
	return LowerIntoRustBuffer[*[]byte](c, value)
}

func (_ FfiConverterOptionalBytes) Write(writer io.Writer, value *[]byte) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterBytesINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalBytes struct {}

func (_ FfiDestroyerOptionalBytes) Destroy(value *[]byte) {
	if value != nil {
		FfiDestroyerBytes{}.Destroy(*value)
	}
}

type FfiConverterOptionalAddress struct{}

var FfiConverterOptionalAddressINSTANCE = FfiConverterOptionalAddress{}

func (c FfiConverterOptionalAddress) Lift(rb RustBufferI) **Address {
	return LiftFromRustBuffer[**Address](c, rb)
}

func (_ FfiConverterOptionalAddress) Read(reader io.Reader) **Address {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterAddressINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalAddress) Lower(value **Address) C.RustBuffer {
	return LowerIntoRustBuffer[**Address](c, value)
}

func (_ FfiConverterOptionalAddress) Write(writer io.Writer, value **Address) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterAddressINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalAddress struct {}

func (_ FfiDestroyerOptionalAddress) Destroy(value **Address) {
	if value != nil {
		FfiDestroyerAddress{}.Destroy(*value)
	}
}

type FfiConverterOptionalBatchSendStatus struct{}

var FfiConverterOptionalBatchSendStatusINSTANCE = FfiConverterOptionalBatchSendStatus{}

func (c FfiConverterOptionalBatchSendStatus) Lift(rb RustBufferI) **BatchSendStatus {
	return LiftFromRustBuffer[**BatchSendStatus](c, rb)
}

func (_ FfiConverterOptionalBatchSendStatus) Read(reader io.Reader) **BatchSendStatus {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterBatchSendStatusINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalBatchSendStatus) Lower(value **BatchSendStatus) C.RustBuffer {
	return LowerIntoRustBuffer[**BatchSendStatus](c, value)
}

func (_ FfiConverterOptionalBatchSendStatus) Write(writer io.Writer, value **BatchSendStatus) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterBatchSendStatusINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalBatchSendStatus struct {}

func (_ FfiDestroyerOptionalBatchSendStatus) Destroy(value **BatchSendStatus) {
	if value != nil {
		FfiDestroyerBatchSendStatus{}.Destroy(*value)
	}
}

type FfiConverterOptionalCheckpointContentsDigest struct{}

var FfiConverterOptionalCheckpointContentsDigestINSTANCE = FfiConverterOptionalCheckpointContentsDigest{}

func (c FfiConverterOptionalCheckpointContentsDigest) Lift(rb RustBufferI) **CheckpointContentsDigest {
	return LiftFromRustBuffer[**CheckpointContentsDigest](c, rb)
}

func (_ FfiConverterOptionalCheckpointContentsDigest) Read(reader io.Reader) **CheckpointContentsDigest {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterCheckpointContentsDigestINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalCheckpointContentsDigest) Lower(value **CheckpointContentsDigest) C.RustBuffer {
	return LowerIntoRustBuffer[**CheckpointContentsDigest](c, value)
}

func (_ FfiConverterOptionalCheckpointContentsDigest) Write(writer io.Writer, value **CheckpointContentsDigest) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterCheckpointContentsDigestINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalCheckpointContentsDigest struct {}

func (_ FfiDestroyerOptionalCheckpointContentsDigest) Destroy(value **CheckpointContentsDigest) {
	if value != nil {
		FfiDestroyerCheckpointContentsDigest{}.Destroy(*value)
	}
}

type FfiConverterOptionalCheckpointDigest struct{}

var FfiConverterOptionalCheckpointDigestINSTANCE = FfiConverterOptionalCheckpointDigest{}

func (c FfiConverterOptionalCheckpointDigest) Lift(rb RustBufferI) **CheckpointDigest {
	return LiftFromRustBuffer[**CheckpointDigest](c, rb)
}

func (_ FfiConverterOptionalCheckpointDigest) Read(reader io.Reader) **CheckpointDigest {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterCheckpointDigestINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalCheckpointDigest) Lower(value **CheckpointDigest) C.RustBuffer {
	return LowerIntoRustBuffer[**CheckpointDigest](c, value)
}

func (_ FfiConverterOptionalCheckpointDigest) Write(writer io.Writer, value **CheckpointDigest) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterCheckpointDigestINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalCheckpointDigest struct {}

func (_ FfiDestroyerOptionalCheckpointDigest) Destroy(value **CheckpointDigest) {
	if value != nil {
		FfiDestroyerCheckpointDigest{}.Destroy(*value)
	}
}

type FfiConverterOptionalCoinMetadata struct{}

var FfiConverterOptionalCoinMetadataINSTANCE = FfiConverterOptionalCoinMetadata{}

func (c FfiConverterOptionalCoinMetadata) Lift(rb RustBufferI) **CoinMetadata {
	return LiftFromRustBuffer[**CoinMetadata](c, rb)
}

func (_ FfiConverterOptionalCoinMetadata) Read(reader io.Reader) **CoinMetadata {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterCoinMetadataINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalCoinMetadata) Lower(value **CoinMetadata) C.RustBuffer {
	return LowerIntoRustBuffer[**CoinMetadata](c, value)
}

func (_ FfiConverterOptionalCoinMetadata) Write(writer io.Writer, value **CoinMetadata) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterCoinMetadataINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalCoinMetadata struct {}

func (_ FfiDestroyerOptionalCoinMetadata) Destroy(value **CoinMetadata) {
	if value != nil {
		FfiDestroyerCoinMetadata{}.Destroy(*value)
	}
}

type FfiConverterOptionalDynamicFieldOutput struct{}

var FfiConverterOptionalDynamicFieldOutputINSTANCE = FfiConverterOptionalDynamicFieldOutput{}

func (c FfiConverterOptionalDynamicFieldOutput) Lift(rb RustBufferI) **DynamicFieldOutput {
	return LiftFromRustBuffer[**DynamicFieldOutput](c, rb)
}

func (_ FfiConverterOptionalDynamicFieldOutput) Read(reader io.Reader) **DynamicFieldOutput {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterDynamicFieldOutputINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalDynamicFieldOutput) Lower(value **DynamicFieldOutput) C.RustBuffer {
	return LowerIntoRustBuffer[**DynamicFieldOutput](c, value)
}

func (_ FfiConverterOptionalDynamicFieldOutput) Write(writer io.Writer, value **DynamicFieldOutput) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterDynamicFieldOutputINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalDynamicFieldOutput struct {}

func (_ FfiDestroyerOptionalDynamicFieldOutput) Destroy(value **DynamicFieldOutput) {
	if value != nil {
		FfiDestroyerDynamicFieldOutput{}.Destroy(*value)
	}
}

type FfiConverterOptionalEpoch struct{}

var FfiConverterOptionalEpochINSTANCE = FfiConverterOptionalEpoch{}

func (c FfiConverterOptionalEpoch) Lift(rb RustBufferI) **Epoch {
	return LiftFromRustBuffer[**Epoch](c, rb)
}

func (_ FfiConverterOptionalEpoch) Read(reader io.Reader) **Epoch {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterEpochINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalEpoch) Lower(value **Epoch) C.RustBuffer {
	return LowerIntoRustBuffer[**Epoch](c, value)
}

func (_ FfiConverterOptionalEpoch) Write(writer io.Writer, value **Epoch) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterEpochINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalEpoch struct {}

func (_ FfiDestroyerOptionalEpoch) Destroy(value **Epoch) {
	if value != nil {
		FfiDestroyerEpoch{}.Destroy(*value)
	}
}

type FfiConverterOptionalFaucetReceipt struct{}

var FfiConverterOptionalFaucetReceiptINSTANCE = FfiConverterOptionalFaucetReceipt{}

func (c FfiConverterOptionalFaucetReceipt) Lift(rb RustBufferI) **FaucetReceipt {
	return LiftFromRustBuffer[**FaucetReceipt](c, rb)
}

func (_ FfiConverterOptionalFaucetReceipt) Read(reader io.Reader) **FaucetReceipt {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterFaucetReceiptINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalFaucetReceipt) Lower(value **FaucetReceipt) C.RustBuffer {
	return LowerIntoRustBuffer[**FaucetReceipt](c, value)
}

func (_ FfiConverterOptionalFaucetReceipt) Write(writer io.Writer, value **FaucetReceipt) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterFaucetReceiptINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalFaucetReceipt struct {}

func (_ FfiDestroyerOptionalFaucetReceipt) Destroy(value **FaucetReceipt) {
	if value != nil {
		FfiDestroyerFaucetReceipt{}.Destroy(*value)
	}
}

type FfiConverterOptionalMoveFunction struct{}

var FfiConverterOptionalMoveFunctionINSTANCE = FfiConverterOptionalMoveFunction{}

func (c FfiConverterOptionalMoveFunction) Lift(rb RustBufferI) **MoveFunction {
	return LiftFromRustBuffer[**MoveFunction](c, rb)
}

func (_ FfiConverterOptionalMoveFunction) Read(reader io.Reader) **MoveFunction {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterMoveFunctionINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalMoveFunction) Lower(value **MoveFunction) C.RustBuffer {
	return LowerIntoRustBuffer[**MoveFunction](c, value)
}

func (_ FfiConverterOptionalMoveFunction) Write(writer io.Writer, value **MoveFunction) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterMoveFunctionINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalMoveFunction struct {}

func (_ FfiDestroyerOptionalMoveFunction) Destroy(value **MoveFunction) {
	if value != nil {
		FfiDestroyerMoveFunction{}.Destroy(*value)
	}
}

type FfiConverterOptionalMoveModule struct{}

var FfiConverterOptionalMoveModuleINSTANCE = FfiConverterOptionalMoveModule{}

func (c FfiConverterOptionalMoveModule) Lift(rb RustBufferI) **MoveModule {
	return LiftFromRustBuffer[**MoveModule](c, rb)
}

func (_ FfiConverterOptionalMoveModule) Read(reader io.Reader) **MoveModule {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterMoveModuleINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalMoveModule) Lower(value **MoveModule) C.RustBuffer {
	return LowerIntoRustBuffer[**MoveModule](c, value)
}

func (_ FfiConverterOptionalMoveModule) Write(writer io.Writer, value **MoveModule) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterMoveModuleINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalMoveModule struct {}

func (_ FfiDestroyerOptionalMoveModule) Destroy(value **MoveModule) {
	if value != nil {
		FfiDestroyerMoveModule{}.Destroy(*value)
	}
}

type FfiConverterOptionalMovePackage struct{}

var FfiConverterOptionalMovePackageINSTANCE = FfiConverterOptionalMovePackage{}

func (c FfiConverterOptionalMovePackage) Lift(rb RustBufferI) **MovePackage {
	return LiftFromRustBuffer[**MovePackage](c, rb)
}

func (_ FfiConverterOptionalMovePackage) Read(reader io.Reader) **MovePackage {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterMovePackageINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalMovePackage) Lower(value **MovePackage) C.RustBuffer {
	return LowerIntoRustBuffer[**MovePackage](c, value)
}

func (_ FfiConverterOptionalMovePackage) Write(writer io.Writer, value **MovePackage) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterMovePackageINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalMovePackage struct {}

func (_ FfiDestroyerOptionalMovePackage) Destroy(value **MovePackage) {
	if value != nil {
		FfiDestroyerMovePackage{}.Destroy(*value)
	}
}

type FfiConverterOptionalMoveStruct struct{}

var FfiConverterOptionalMoveStructINSTANCE = FfiConverterOptionalMoveStruct{}

func (c FfiConverterOptionalMoveStruct) Lift(rb RustBufferI) **MoveStruct {
	return LiftFromRustBuffer[**MoveStruct](c, rb)
}

func (_ FfiConverterOptionalMoveStruct) Read(reader io.Reader) **MoveStruct {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterMoveStructINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalMoveStruct) Lower(value **MoveStruct) C.RustBuffer {
	return LowerIntoRustBuffer[**MoveStruct](c, value)
}

func (_ FfiConverterOptionalMoveStruct) Write(writer io.Writer, value **MoveStruct) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterMoveStructINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalMoveStruct struct {}

func (_ FfiDestroyerOptionalMoveStruct) Destroy(value **MoveStruct) {
	if value != nil {
		FfiDestroyerMoveStruct{}.Destroy(*value)
	}
}

type FfiConverterOptionalObject struct{}

var FfiConverterOptionalObjectINSTANCE = FfiConverterOptionalObject{}

func (c FfiConverterOptionalObject) Lift(rb RustBufferI) **Object {
	return LiftFromRustBuffer[**Object](c, rb)
}

func (_ FfiConverterOptionalObject) Read(reader io.Reader) **Object {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterObjectINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalObject) Lower(value **Object) C.RustBuffer {
	return LowerIntoRustBuffer[**Object](c, value)
}

func (_ FfiConverterOptionalObject) Write(writer io.Writer, value **Object) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterObjectINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalObject struct {}

func (_ FfiDestroyerOptionalObject) Destroy(value **Object) {
	if value != nil {
		FfiDestroyerObject{}.Destroy(*value)
	}
}

type FfiConverterOptionalObjectFilter struct{}

var FfiConverterOptionalObjectFilterINSTANCE = FfiConverterOptionalObjectFilter{}

func (c FfiConverterOptionalObjectFilter) Lift(rb RustBufferI) **ObjectFilter {
	return LiftFromRustBuffer[**ObjectFilter](c, rb)
}

func (_ FfiConverterOptionalObjectFilter) Read(reader io.Reader) **ObjectFilter {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterObjectFilterINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalObjectFilter) Lower(value **ObjectFilter) C.RustBuffer {
	return LowerIntoRustBuffer[**ObjectFilter](c, value)
}

func (_ FfiConverterOptionalObjectFilter) Write(writer io.Writer, value **ObjectFilter) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterObjectFilterINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalObjectFilter struct {}

func (_ FfiDestroyerOptionalObjectFilter) Destroy(value **ObjectFilter) {
	if value != nil {
		FfiDestroyerObjectFilter{}.Destroy(*value)
	}
}

type FfiConverterOptionalObjectId struct{}

var FfiConverterOptionalObjectIdINSTANCE = FfiConverterOptionalObjectId{}

func (c FfiConverterOptionalObjectId) Lift(rb RustBufferI) **ObjectId {
	return LiftFromRustBuffer[**ObjectId](c, rb)
}

func (_ FfiConverterOptionalObjectId) Read(reader io.Reader) **ObjectId {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterObjectIdINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalObjectId) Lower(value **ObjectId) C.RustBuffer {
	return LowerIntoRustBuffer[**ObjectId](c, value)
}

func (_ FfiConverterOptionalObjectId) Write(writer io.Writer, value **ObjectId) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterObjectIdINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalObjectId struct {}

func (_ FfiDestroyerOptionalObjectId) Destroy(value **ObjectId) {
	if value != nil {
		FfiDestroyerObjectId{}.Destroy(*value)
	}
}

type FfiConverterOptionalProtocolConfigs struct{}

var FfiConverterOptionalProtocolConfigsINSTANCE = FfiConverterOptionalProtocolConfigs{}

func (c FfiConverterOptionalProtocolConfigs) Lift(rb RustBufferI) **ProtocolConfigs {
	return LiftFromRustBuffer[**ProtocolConfigs](c, rb)
}

func (_ FfiConverterOptionalProtocolConfigs) Read(reader io.Reader) **ProtocolConfigs {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterProtocolConfigsINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalProtocolConfigs) Lower(value **ProtocolConfigs) C.RustBuffer {
	return LowerIntoRustBuffer[**ProtocolConfigs](c, value)
}

func (_ FfiConverterOptionalProtocolConfigs) Write(writer io.Writer, value **ProtocolConfigs) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterProtocolConfigsINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalProtocolConfigs struct {}

func (_ FfiDestroyerOptionalProtocolConfigs) Destroy(value **ProtocolConfigs) {
	if value != nil {
		FfiDestroyerProtocolConfigs{}.Destroy(*value)
	}
}

type FfiConverterOptionalSignedTransaction struct{}

var FfiConverterOptionalSignedTransactionINSTANCE = FfiConverterOptionalSignedTransaction{}

func (c FfiConverterOptionalSignedTransaction) Lift(rb RustBufferI) **SignedTransaction {
	return LiftFromRustBuffer[**SignedTransaction](c, rb)
}

func (_ FfiConverterOptionalSignedTransaction) Read(reader io.Reader) **SignedTransaction {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSignedTransactionINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSignedTransaction) Lower(value **SignedTransaction) C.RustBuffer {
	return LowerIntoRustBuffer[**SignedTransaction](c, value)
}

func (_ FfiConverterOptionalSignedTransaction) Write(writer io.Writer, value **SignedTransaction) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSignedTransactionINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSignedTransaction struct {}

func (_ FfiDestroyerOptionalSignedTransaction) Destroy(value **SignedTransaction) {
	if value != nil {
		FfiDestroyerSignedTransaction{}.Destroy(*value)
	}
}

type FfiConverterOptionalTransactionDataEffects struct{}

var FfiConverterOptionalTransactionDataEffectsINSTANCE = FfiConverterOptionalTransactionDataEffects{}

func (c FfiConverterOptionalTransactionDataEffects) Lift(rb RustBufferI) **TransactionDataEffects {
	return LiftFromRustBuffer[**TransactionDataEffects](c, rb)
}

func (_ FfiConverterOptionalTransactionDataEffects) Read(reader io.Reader) **TransactionDataEffects {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTransactionDataEffectsINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTransactionDataEffects) Lower(value **TransactionDataEffects) C.RustBuffer {
	return LowerIntoRustBuffer[**TransactionDataEffects](c, value)
}

func (_ FfiConverterOptionalTransactionDataEffects) Write(writer io.Writer, value **TransactionDataEffects) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTransactionDataEffectsINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTransactionDataEffects struct {}

func (_ FfiDestroyerOptionalTransactionDataEffects) Destroy(value **TransactionDataEffects) {
	if value != nil {
		FfiDestroyerTransactionDataEffects{}.Destroy(*value)
	}
}

type FfiConverterOptionalTransactionEffects struct{}

var FfiConverterOptionalTransactionEffectsINSTANCE = FfiConverterOptionalTransactionEffects{}

func (c FfiConverterOptionalTransactionEffects) Lift(rb RustBufferI) **TransactionEffects {
	return LiftFromRustBuffer[**TransactionEffects](c, rb)
}

func (_ FfiConverterOptionalTransactionEffects) Read(reader io.Reader) **TransactionEffects {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTransactionEffectsINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTransactionEffects) Lower(value **TransactionEffects) C.RustBuffer {
	return LowerIntoRustBuffer[**TransactionEffects](c, value)
}

func (_ FfiConverterOptionalTransactionEffects) Write(writer io.Writer, value **TransactionEffects) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTransactionEffectsINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTransactionEffects struct {}

func (_ FfiDestroyerOptionalTransactionEffects) Destroy(value **TransactionEffects) {
	if value != nil {
		FfiDestroyerTransactionEffects{}.Destroy(*value)
	}
}

type FfiConverterOptionalCheckpointSummary struct{}

var FfiConverterOptionalCheckpointSummaryINSTANCE = FfiConverterOptionalCheckpointSummary{}

func (c FfiConverterOptionalCheckpointSummary) Lift(rb RustBufferI) *CheckpointSummary {
	return LiftFromRustBuffer[*CheckpointSummary](c, rb)
}

func (_ FfiConverterOptionalCheckpointSummary) Read(reader io.Reader) *CheckpointSummary {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterCheckpointSummaryINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalCheckpointSummary) Lower(value *CheckpointSummary) C.RustBuffer {
	return LowerIntoRustBuffer[*CheckpointSummary](c, value)
}

func (_ FfiConverterOptionalCheckpointSummary) Write(writer io.Writer, value *CheckpointSummary) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterCheckpointSummaryINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalCheckpointSummary struct {}

func (_ FfiDestroyerOptionalCheckpointSummary) Destroy(value *CheckpointSummary) {
	if value != nil {
		FfiDestroyerCheckpointSummary{}.Destroy(*value)
	}
}

type FfiConverterOptionalEndOfEpochData struct{}

var FfiConverterOptionalEndOfEpochDataINSTANCE = FfiConverterOptionalEndOfEpochData{}

func (c FfiConverterOptionalEndOfEpochData) Lift(rb RustBufferI) *EndOfEpochData {
	return LiftFromRustBuffer[*EndOfEpochData](c, rb)
}

func (_ FfiConverterOptionalEndOfEpochData) Read(reader io.Reader) *EndOfEpochData {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterEndOfEpochDataINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalEndOfEpochData) Lower(value *EndOfEpochData) C.RustBuffer {
	return LowerIntoRustBuffer[*EndOfEpochData](c, value)
}

func (_ FfiConverterOptionalEndOfEpochData) Write(writer io.Writer, value *EndOfEpochData) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterEndOfEpochDataINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalEndOfEpochData struct {}

func (_ FfiDestroyerOptionalEndOfEpochData) Destroy(value *EndOfEpochData) {
	if value != nil {
		FfiDestroyerEndOfEpochData{}.Destroy(*value)
	}
}

type FfiConverterOptionalEventFilter struct{}

var FfiConverterOptionalEventFilterINSTANCE = FfiConverterOptionalEventFilter{}

func (c FfiConverterOptionalEventFilter) Lift(rb RustBufferI) *EventFilter {
	return LiftFromRustBuffer[*EventFilter](c, rb)
}

func (_ FfiConverterOptionalEventFilter) Read(reader io.Reader) *EventFilter {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterEventFilterINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalEventFilter) Lower(value *EventFilter) C.RustBuffer {
	return LowerIntoRustBuffer[*EventFilter](c, value)
}

func (_ FfiConverterOptionalEventFilter) Write(writer io.Writer, value *EventFilter) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterEventFilterINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalEventFilter struct {}

func (_ FfiDestroyerOptionalEventFilter) Destroy(value *EventFilter) {
	if value != nil {
		FfiDestroyerEventFilter{}.Destroy(*value)
	}
}

type FfiConverterOptionalTransactionsFilter struct{}

var FfiConverterOptionalTransactionsFilterINSTANCE = FfiConverterOptionalTransactionsFilter{}

func (c FfiConverterOptionalTransactionsFilter) Lift(rb RustBufferI) *TransactionsFilter {
	return LiftFromRustBuffer[*TransactionsFilter](c, rb)
}

func (_ FfiConverterOptionalTransactionsFilter) Read(reader io.Reader) *TransactionsFilter {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTransactionsFilterINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTransactionsFilter) Lower(value *TransactionsFilter) C.RustBuffer {
	return LowerIntoRustBuffer[*TransactionsFilter](c, value)
}

func (_ FfiConverterOptionalTransactionsFilter) Write(writer io.Writer, value *TransactionsFilter) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTransactionsFilterINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTransactionsFilter struct {}

func (_ FfiDestroyerOptionalTransactionsFilter) Destroy(value *TransactionsFilter) {
	if value != nil {
		FfiDestroyerTransactionsFilter{}.Destroy(*value)
	}
}

type FfiConverterOptionalTransactionBlockKindInput struct{}

var FfiConverterOptionalTransactionBlockKindInputINSTANCE = FfiConverterOptionalTransactionBlockKindInput{}

func (c FfiConverterOptionalTransactionBlockKindInput) Lift(rb RustBufferI) *TransactionBlockKindInput {
	return LiftFromRustBuffer[*TransactionBlockKindInput](c, rb)
}

func (_ FfiConverterOptionalTransactionBlockKindInput) Read(reader io.Reader) *TransactionBlockKindInput {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTransactionBlockKindInputINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTransactionBlockKindInput) Lower(value *TransactionBlockKindInput) C.RustBuffer {
	return LowerIntoRustBuffer[*TransactionBlockKindInput](c, value)
}

func (_ FfiConverterOptionalTransactionBlockKindInput) Write(writer io.Writer, value *TransactionBlockKindInput) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTransactionBlockKindInputINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTransactionBlockKindInput struct {}

func (_ FfiDestroyerOptionalTransactionBlockKindInput) Destroy(value *TransactionBlockKindInput) {
	if value != nil {
		FfiDestroyerTransactionBlockKindInput{}.Destroy(*value)
	}
}

type FfiConverterOptionalSequenceString struct{}

var FfiConverterOptionalSequenceStringINSTANCE = FfiConverterOptionalSequenceString{}

func (c FfiConverterOptionalSequenceString) Lift(rb RustBufferI) *[]string {
	return LiftFromRustBuffer[*[]string](c, rb)
}

func (_ FfiConverterOptionalSequenceString) Read(reader io.Reader) *[]string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSequenceStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSequenceString) Lower(value *[]string) C.RustBuffer {
	return LowerIntoRustBuffer[*[]string](c, value)
}

func (_ FfiConverterOptionalSequenceString) Write(writer io.Writer, value *[]string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSequenceStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSequenceString struct {}

func (_ FfiDestroyerOptionalSequenceString) Destroy(value *[]string) {
	if value != nil {
		FfiDestroyerSequenceString{}.Destroy(*value)
	}
}

type FfiConverterOptionalSequenceObjectRef struct{}

var FfiConverterOptionalSequenceObjectRefINSTANCE = FfiConverterOptionalSequenceObjectRef{}

func (c FfiConverterOptionalSequenceObjectRef) Lift(rb RustBufferI) *[]*ObjectRef {
	return LiftFromRustBuffer[*[]*ObjectRef](c, rb)
}

func (_ FfiConverterOptionalSequenceObjectRef) Read(reader io.Reader) *[]*ObjectRef {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSequenceObjectRefINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSequenceObjectRef) Lower(value *[]*ObjectRef) C.RustBuffer {
	return LowerIntoRustBuffer[*[]*ObjectRef](c, value)
}

func (_ FfiConverterOptionalSequenceObjectRef) Write(writer io.Writer, value *[]*ObjectRef) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSequenceObjectRefINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSequenceObjectRef struct {}

func (_ FfiDestroyerOptionalSequenceObjectRef) Destroy(value *[]*ObjectRef) {
	if value != nil {
		FfiDestroyerSequenceObjectRef{}.Destroy(*value)
	}
}

type FfiConverterOptionalTypeValue struct{}

var FfiConverterOptionalTypeValueINSTANCE = FfiConverterOptionalTypeValue{}

func (c FfiConverterOptionalTypeValue) Lift(rb RustBufferI) *Value {
	return LiftFromRustBuffer[*Value](c, rb)
}

func (_ FfiConverterOptionalTypeValue) Read(reader io.Reader) *Value {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTypeValueINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTypeValue) Lower(value *Value) C.RustBuffer {
	return LowerIntoRustBuffer[*Value](c, value)
}

func (_ FfiConverterOptionalTypeValue) Write(writer io.Writer, value *Value) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTypeValueINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTypeValue struct {}

func (_ FfiDestroyerOptionalTypeValue) Destroy(value *Value) {
	if value != nil {
		FfiDestroyerTypeValue{}.Destroy(*value)
	}
}

type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) C.RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct {}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)
	}
}

type FfiConverterSequenceCheckpointCommitment struct{}

var FfiConverterSequenceCheckpointCommitmentINSTANCE = FfiConverterSequenceCheckpointCommitment{}

func (c FfiConverterSequenceCheckpointCommitment) Lift(rb RustBufferI) []*CheckpointCommitment {
	return LiftFromRustBuffer[[]*CheckpointCommitment](c, rb)
}

func (c FfiConverterSequenceCheckpointCommitment) Read(reader io.Reader) []*CheckpointCommitment {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*CheckpointCommitment, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterCheckpointCommitmentINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceCheckpointCommitment) Lower(value []*CheckpointCommitment) C.RustBuffer {
	return LowerIntoRustBuffer[[]*CheckpointCommitment](c, value)
}

func (c FfiConverterSequenceCheckpointCommitment) Write(writer io.Writer, value []*CheckpointCommitment) {
	if len(value) > math.MaxInt32 {
		panic("[]*CheckpointCommitment is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterCheckpointCommitmentINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceCheckpointCommitment struct {}

func (FfiDestroyerSequenceCheckpointCommitment) Destroy(sequence []*CheckpointCommitment) {
	for _, value := range sequence {
		FfiDestroyerCheckpointCommitment{}.Destroy(value)
	}
}

type FfiConverterSequenceCoin struct{}

var FfiConverterSequenceCoinINSTANCE = FfiConverterSequenceCoin{}

func (c FfiConverterSequenceCoin) Lift(rb RustBufferI) []*Coin {
	return LiftFromRustBuffer[[]*Coin](c, rb)
}

func (c FfiConverterSequenceCoin) Read(reader io.Reader) []*Coin {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*Coin, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterCoinINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceCoin) Lower(value []*Coin) C.RustBuffer {
	return LowerIntoRustBuffer[[]*Coin](c, value)
}

func (c FfiConverterSequenceCoin) Write(writer io.Writer, value []*Coin) {
	if len(value) > math.MaxInt32 {
		panic("[]*Coin is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterCoinINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceCoin struct {}

func (FfiDestroyerSequenceCoin) Destroy(sequence []*Coin) {
	for _, value := range sequence {
		FfiDestroyerCoin{}.Destroy(value)
	}
}

type FfiConverterSequenceDynamicFieldOutput struct{}

var FfiConverterSequenceDynamicFieldOutputINSTANCE = FfiConverterSequenceDynamicFieldOutput{}

func (c FfiConverterSequenceDynamicFieldOutput) Lift(rb RustBufferI) []*DynamicFieldOutput {
	return LiftFromRustBuffer[[]*DynamicFieldOutput](c, rb)
}

func (c FfiConverterSequenceDynamicFieldOutput) Read(reader io.Reader) []*DynamicFieldOutput {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*DynamicFieldOutput, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterDynamicFieldOutputINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceDynamicFieldOutput) Lower(value []*DynamicFieldOutput) C.RustBuffer {
	return LowerIntoRustBuffer[[]*DynamicFieldOutput](c, value)
}

func (c FfiConverterSequenceDynamicFieldOutput) Write(writer io.Writer, value []*DynamicFieldOutput) {
	if len(value) > math.MaxInt32 {
		panic("[]*DynamicFieldOutput is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterDynamicFieldOutputINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceDynamicFieldOutput struct {}

func (FfiDestroyerSequenceDynamicFieldOutput) Destroy(sequence []*DynamicFieldOutput) {
	for _, value := range sequence {
		FfiDestroyerDynamicFieldOutput{}.Destroy(value)
	}
}

type FfiConverterSequenceEndOfEpochTransactionKind struct{}

var FfiConverterSequenceEndOfEpochTransactionKindINSTANCE = FfiConverterSequenceEndOfEpochTransactionKind{}

func (c FfiConverterSequenceEndOfEpochTransactionKind) Lift(rb RustBufferI) []*EndOfEpochTransactionKind {
	return LiftFromRustBuffer[[]*EndOfEpochTransactionKind](c, rb)
}

func (c FfiConverterSequenceEndOfEpochTransactionKind) Read(reader io.Reader) []*EndOfEpochTransactionKind {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*EndOfEpochTransactionKind, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterEndOfEpochTransactionKindINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceEndOfEpochTransactionKind) Lower(value []*EndOfEpochTransactionKind) C.RustBuffer {
	return LowerIntoRustBuffer[[]*EndOfEpochTransactionKind](c, value)
}

func (c FfiConverterSequenceEndOfEpochTransactionKind) Write(writer io.Writer, value []*EndOfEpochTransactionKind) {
	if len(value) > math.MaxInt32 {
		panic("[]*EndOfEpochTransactionKind is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterEndOfEpochTransactionKindINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceEndOfEpochTransactionKind struct {}

func (FfiDestroyerSequenceEndOfEpochTransactionKind) Destroy(sequence []*EndOfEpochTransactionKind) {
	for _, value := range sequence {
		FfiDestroyerEndOfEpochTransactionKind{}.Destroy(value)
	}
}

type FfiConverterSequenceEpoch struct{}

var FfiConverterSequenceEpochINSTANCE = FfiConverterSequenceEpoch{}

func (c FfiConverterSequenceEpoch) Lift(rb RustBufferI) []*Epoch {
	return LiftFromRustBuffer[[]*Epoch](c, rb)
}

func (c FfiConverterSequenceEpoch) Read(reader io.Reader) []*Epoch {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*Epoch, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterEpochINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceEpoch) Lower(value []*Epoch) C.RustBuffer {
	return LowerIntoRustBuffer[[]*Epoch](c, value)
}

func (c FfiConverterSequenceEpoch) Write(writer io.Writer, value []*Epoch) {
	if len(value) > math.MaxInt32 {
		panic("[]*Epoch is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterEpochINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceEpoch struct {}

func (FfiDestroyerSequenceEpoch) Destroy(sequence []*Epoch) {
	for _, value := range sequence {
		FfiDestroyerEpoch{}.Destroy(value)
	}
}

type FfiConverterSequenceEvent struct{}

var FfiConverterSequenceEventINSTANCE = FfiConverterSequenceEvent{}

func (c FfiConverterSequenceEvent) Lift(rb RustBufferI) []*Event {
	return LiftFromRustBuffer[[]*Event](c, rb)
}

func (c FfiConverterSequenceEvent) Read(reader io.Reader) []*Event {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*Event, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterEventINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceEvent) Lower(value []*Event) C.RustBuffer {
	return LowerIntoRustBuffer[[]*Event](c, value)
}

func (c FfiConverterSequenceEvent) Write(writer io.Writer, value []*Event) {
	if len(value) > math.MaxInt32 {
		panic("[]*Event is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterEventINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceEvent struct {}

func (FfiDestroyerSequenceEvent) Destroy(sequence []*Event) {
	for _, value := range sequence {
		FfiDestroyerEvent{}.Destroy(value)
	}
}

type FfiConverterSequenceMovePackage struct{}

var FfiConverterSequenceMovePackageINSTANCE = FfiConverterSequenceMovePackage{}

func (c FfiConverterSequenceMovePackage) Lift(rb RustBufferI) []*MovePackage {
	return LiftFromRustBuffer[[]*MovePackage](c, rb)
}

func (c FfiConverterSequenceMovePackage) Read(reader io.Reader) []*MovePackage {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*MovePackage, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterMovePackageINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceMovePackage) Lower(value []*MovePackage) C.RustBuffer {
	return LowerIntoRustBuffer[[]*MovePackage](c, value)
}

func (c FfiConverterSequenceMovePackage) Write(writer io.Writer, value []*MovePackage) {
	if len(value) > math.MaxInt32 {
		panic("[]*MovePackage is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterMovePackageINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceMovePackage struct {}

func (FfiDestroyerSequenceMovePackage) Destroy(sequence []*MovePackage) {
	for _, value := range sequence {
		FfiDestroyerMovePackage{}.Destroy(value)
	}
}

type FfiConverterSequenceObject struct{}

var FfiConverterSequenceObjectINSTANCE = FfiConverterSequenceObject{}

func (c FfiConverterSequenceObject) Lift(rb RustBufferI) []*Object {
	return LiftFromRustBuffer[[]*Object](c, rb)
}

func (c FfiConverterSequenceObject) Read(reader io.Reader) []*Object {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*Object, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterObjectINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceObject) Lower(value []*Object) C.RustBuffer {
	return LowerIntoRustBuffer[[]*Object](c, value)
}

func (c FfiConverterSequenceObject) Write(writer io.Writer, value []*Object) {
	if len(value) > math.MaxInt32 {
		panic("[]*Object is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterObjectINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceObject struct {}

func (FfiDestroyerSequenceObject) Destroy(sequence []*Object) {
	for _, value := range sequence {
		FfiDestroyerObject{}.Destroy(value)
	}
}

type FfiConverterSequenceObjectRef struct{}

var FfiConverterSequenceObjectRefINSTANCE = FfiConverterSequenceObjectRef{}

func (c FfiConverterSequenceObjectRef) Lift(rb RustBufferI) []*ObjectRef {
	return LiftFromRustBuffer[[]*ObjectRef](c, rb)
}

func (c FfiConverterSequenceObjectRef) Read(reader io.Reader) []*ObjectRef {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*ObjectRef, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterObjectRefINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceObjectRef) Lower(value []*ObjectRef) C.RustBuffer {
	return LowerIntoRustBuffer[[]*ObjectRef](c, value)
}

func (c FfiConverterSequenceObjectRef) Write(writer io.Writer, value []*ObjectRef) {
	if len(value) > math.MaxInt32 {
		panic("[]*ObjectRef is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterObjectRefINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceObjectRef struct {}

func (FfiDestroyerSequenceObjectRef) Destroy(sequence []*ObjectRef) {
	for _, value := range sequence {
		FfiDestroyerObjectRef{}.Destroy(value)
	}
}

type FfiConverterSequenceSignedTransaction struct{}

var FfiConverterSequenceSignedTransactionINSTANCE = FfiConverterSequenceSignedTransaction{}

func (c FfiConverterSequenceSignedTransaction) Lift(rb RustBufferI) []*SignedTransaction {
	return LiftFromRustBuffer[[]*SignedTransaction](c, rb)
}

func (c FfiConverterSequenceSignedTransaction) Read(reader io.Reader) []*SignedTransaction {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*SignedTransaction, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterSignedTransactionINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceSignedTransaction) Lower(value []*SignedTransaction) C.RustBuffer {
	return LowerIntoRustBuffer[[]*SignedTransaction](c, value)
}

func (c FfiConverterSequenceSignedTransaction) Write(writer io.Writer, value []*SignedTransaction) {
	if len(value) > math.MaxInt32 {
		panic("[]*SignedTransaction is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterSignedTransactionINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceSignedTransaction struct {}

func (FfiDestroyerSequenceSignedTransaction) Destroy(sequence []*SignedTransaction) {
	for _, value := range sequence {
		FfiDestroyerSignedTransaction{}.Destroy(value)
	}
}

type FfiConverterSequenceTransactionDataEffects struct{}

var FfiConverterSequenceTransactionDataEffectsINSTANCE = FfiConverterSequenceTransactionDataEffects{}

func (c FfiConverterSequenceTransactionDataEffects) Lift(rb RustBufferI) []*TransactionDataEffects {
	return LiftFromRustBuffer[[]*TransactionDataEffects](c, rb)
}

func (c FfiConverterSequenceTransactionDataEffects) Read(reader io.Reader) []*TransactionDataEffects {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*TransactionDataEffects, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTransactionDataEffectsINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTransactionDataEffects) Lower(value []*TransactionDataEffects) C.RustBuffer {
	return LowerIntoRustBuffer[[]*TransactionDataEffects](c, value)
}

func (c FfiConverterSequenceTransactionDataEffects) Write(writer io.Writer, value []*TransactionDataEffects) {
	if len(value) > math.MaxInt32 {
		panic("[]*TransactionDataEffects is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTransactionDataEffectsINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTransactionDataEffects struct {}

func (FfiDestroyerSequenceTransactionDataEffects) Destroy(sequence []*TransactionDataEffects) {
	for _, value := range sequence {
		FfiDestroyerTransactionDataEffects{}.Destroy(value)
	}
}

type FfiConverterSequenceTransactionEffects struct{}

var FfiConverterSequenceTransactionEffectsINSTANCE = FfiConverterSequenceTransactionEffects{}

func (c FfiConverterSequenceTransactionEffects) Lift(rb RustBufferI) []*TransactionEffects {
	return LiftFromRustBuffer[[]*TransactionEffects](c, rb)
}

func (c FfiConverterSequenceTransactionEffects) Read(reader io.Reader) []*TransactionEffects {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*TransactionEffects, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTransactionEffectsINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTransactionEffects) Lower(value []*TransactionEffects) C.RustBuffer {
	return LowerIntoRustBuffer[[]*TransactionEffects](c, value)
}

func (c FfiConverterSequenceTransactionEffects) Write(writer io.Writer, value []*TransactionEffects) {
	if len(value) > math.MaxInt32 {
		panic("[]*TransactionEffects is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTransactionEffectsINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTransactionEffects struct {}

func (FfiDestroyerSequenceTransactionEffects) Destroy(sequence []*TransactionEffects) {
	for _, value := range sequence {
		FfiDestroyerTransactionEffects{}.Destroy(value)
	}
}

type FfiConverterSequenceUserSignature struct{}

var FfiConverterSequenceUserSignatureINSTANCE = FfiConverterSequenceUserSignature{}

func (c FfiConverterSequenceUserSignature) Lift(rb RustBufferI) []*UserSignature {
	return LiftFromRustBuffer[[]*UserSignature](c, rb)
}

func (c FfiConverterSequenceUserSignature) Read(reader io.Reader) []*UserSignature {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*UserSignature, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUserSignatureINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUserSignature) Lower(value []*UserSignature) C.RustBuffer {
	return LowerIntoRustBuffer[[]*UserSignature](c, value)
}

func (c FfiConverterSequenceUserSignature) Write(writer io.Writer, value []*UserSignature) {
	if len(value) > math.MaxInt32 {
		panic("[]*UserSignature is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUserSignatureINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUserSignature struct {}

func (FfiDestroyerSequenceUserSignature) Destroy(sequence []*UserSignature) {
	for _, value := range sequence {
		FfiDestroyerUserSignature{}.Destroy(value)
	}
}

type FfiConverterSequenceValidator struct{}

var FfiConverterSequenceValidatorINSTANCE = FfiConverterSequenceValidator{}

func (c FfiConverterSequenceValidator) Lift(rb RustBufferI) []*Validator {
	return LiftFromRustBuffer[[]*Validator](c, rb)
}

func (c FfiConverterSequenceValidator) Read(reader io.Reader) []*Validator {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]*Validator, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterValidatorINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceValidator) Lower(value []*Validator) C.RustBuffer {
	return LowerIntoRustBuffer[[]*Validator](c, value)
}

func (c FfiConverterSequenceValidator) Write(writer io.Writer, value []*Validator) {
	if len(value) > math.MaxInt32 {
		panic("[]*Validator is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterValidatorINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceValidator struct {}

func (FfiDestroyerSequenceValidator) Destroy(sequence []*Validator) {
	for _, value := range sequence {
		FfiDestroyerValidator{}.Destroy(value)
	}
}

type FfiConverterSequenceCheckpointSummary struct{}

var FfiConverterSequenceCheckpointSummaryINSTANCE = FfiConverterSequenceCheckpointSummary{}

func (c FfiConverterSequenceCheckpointSummary) Lift(rb RustBufferI) []CheckpointSummary {
	return LiftFromRustBuffer[[]CheckpointSummary](c, rb)
}

func (c FfiConverterSequenceCheckpointSummary) Read(reader io.Reader) []CheckpointSummary {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]CheckpointSummary, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterCheckpointSummaryINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceCheckpointSummary) Lower(value []CheckpointSummary) C.RustBuffer {
	return LowerIntoRustBuffer[[]CheckpointSummary](c, value)
}

func (c FfiConverterSequenceCheckpointSummary) Write(writer io.Writer, value []CheckpointSummary) {
	if len(value) > math.MaxInt32 {
		panic("[]CheckpointSummary is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterCheckpointSummaryINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceCheckpointSummary struct {}

func (FfiDestroyerSequenceCheckpointSummary) Destroy(sequence []CheckpointSummary) {
	for _, value := range sequence {
		FfiDestroyerCheckpointSummary{}.Destroy(value)
	}
}

type FfiConverterSequenceObjectReference struct{}

var FfiConverterSequenceObjectReferenceINSTANCE = FfiConverterSequenceObjectReference{}

func (c FfiConverterSequenceObjectReference) Lift(rb RustBufferI) []ObjectReference {
	return LiftFromRustBuffer[[]ObjectReference](c, rb)
}

func (c FfiConverterSequenceObjectReference) Read(reader io.Reader) []ObjectReference {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]ObjectReference, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterObjectReferenceINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceObjectReference) Lower(value []ObjectReference) C.RustBuffer {
	return LowerIntoRustBuffer[[]ObjectReference](c, value)
}

func (c FfiConverterSequenceObjectReference) Write(writer io.Writer, value []ObjectReference) {
	if len(value) > math.MaxInt32 {
		panic("[]ObjectReference is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterObjectReferenceINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceObjectReference struct {}

func (FfiDestroyerSequenceObjectReference) Destroy(sequence []ObjectReference) {
	for _, value := range sequence {
		FfiDestroyerObjectReference{}.Destroy(value)
	}
}

type FfiConverterSequenceValidatorCommitteeMember struct{}

var FfiConverterSequenceValidatorCommitteeMemberINSTANCE = FfiConverterSequenceValidatorCommitteeMember{}

func (c FfiConverterSequenceValidatorCommitteeMember) Lift(rb RustBufferI) []ValidatorCommitteeMember {
	return LiftFromRustBuffer[[]ValidatorCommitteeMember](c, rb)
}

func (c FfiConverterSequenceValidatorCommitteeMember) Read(reader io.Reader) []ValidatorCommitteeMember {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]ValidatorCommitteeMember, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterValidatorCommitteeMemberINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceValidatorCommitteeMember) Lower(value []ValidatorCommitteeMember) C.RustBuffer {
	return LowerIntoRustBuffer[[]ValidatorCommitteeMember](c, value)
}

func (c FfiConverterSequenceValidatorCommitteeMember) Write(writer io.Writer, value []ValidatorCommitteeMember) {
	if len(value) > math.MaxInt32 {
		panic("[]ValidatorCommitteeMember is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterValidatorCommitteeMemberINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceValidatorCommitteeMember struct {}

func (FfiDestroyerSequenceValidatorCommitteeMember) Destroy(sequence []ValidatorCommitteeMember) {
	for _, value := range sequence {
		FfiDestroyerValidatorCommitteeMember{}.Destroy(value)
	}
}
/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 * It's also what we have an external type that references a custom type.
 */
type Value = string
type FfiConverterTypeValue = FfiConverterString
type FfiDestroyerTypeValue = FfiDestroyerString
var FfiConverterTypeValueINSTANCE = FfiConverterString{}


const (
	uniffiRustFuturePollReady      int8 = 0
	uniffiRustFuturePollMaybeReady int8 = 1
)

type rustFuturePollFunc func(C.uint64_t, C.UniffiRustFutureContinuationCallback, C.uint64_t)
type rustFutureCompleteFunc[T any] func(C.uint64_t, *C.RustCallStatus) T
type rustFutureFreeFunc func(C.uint64_t)

//export iota_sdk_ffi_uniffiFutureContinuationCallback
func iota_sdk_ffi_uniffiFutureContinuationCallback(data C.uint64_t, pollResult C.int8_t) {
	h := cgo.Handle(uintptr(data))
	waiter := h.Value().(chan int8)
	waiter <- int8(pollResult)
}

func uniffiRustCallAsync[E any, T any, F any](
	errConverter BufReader[*E],
	completeFunc rustFutureCompleteFunc[F],
	liftFunc func(F) T,
	rustFuture C.uint64_t,
	pollFunc rustFuturePollFunc,
	freeFunc rustFutureFreeFunc,
) (T, *E) {
	defer freeFunc(rustFuture)

	pollResult := int8(-1)
	waiter := make(chan int8, 1)

	chanHandle := cgo.NewHandle(waiter)
	defer chanHandle.Delete()

	for pollResult != uniffiRustFuturePollReady {
		pollFunc(
			rustFuture,
			(C.UniffiRustFutureContinuationCallback)(C.iota_sdk_ffi_uniffiFutureContinuationCallback),
			C.uint64_t(chanHandle),
		)
		pollResult = <-waiter
	}

	var goValue T
	var ffiValue F
	var err *E

	ffiValue, err = rustCallWithError(errConverter, func(status *C.RustCallStatus) F {
		return completeFunc(rustFuture, status)
	})
	if err != nil {
		return goValue, err
	}
	return liftFunc(ffiValue), nil
}

//export iota_sdk_ffi_uniffiFreeGorutine
func iota_sdk_ffi_uniffiFreeGorutine(data C.uint64_t) {
	handle := cgo.Handle(uintptr(data))
	defer handle.Delete()

	guard := handle.Value().(chan struct{})
	guard <- struct{}{}
}

