// Compute an event ID from Go through the C ABI.
//
//	cargo build -p rezzy-ffi
//	cd rezzy-ffi/examples/go && go run . event-id 12 event.json
package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../../target/debug -lrezzy_ffi -Wl,-rpath,${SRCDIR}/../../../target/debug
#include <stdlib.h>
#include "rezzy.h"
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

const (
	eventIDOperation = iota
	verifyContentHashOperation
	hashEventsOperation
)

// EventID returns the reference-hash event ID of a JSON event under roomVersion.
// Parsing and hashing failures, including opaque-ID versions, return an error.
func EventID(roomVersion string, event []byte) (string, error) {
	return call(roomVersion, event, eventIDOperation)
}

// VerifyContentHash checks the event's hashes.sha256 under roomVersion.
// It returns an error for malformed input or a failed content-hash check.
func VerifyContentHash(roomVersion string, event []byte) error {
	_, err := call(roomVersion, event, verifyContentHashOperation)
	return err
}

// HashEventsJSONL returns an event report for each nonblank JSONL line.
// Per-event failures remain in the report; invalid UTF-8 or empty input returns
// an error. Unsupported versions are handled per event rather than rejected up front.
func HashEventsJSONL(roomVersion string, jsonl []byte) (string, error) {
	return call(roomVersion, jsonl, hashEventsOperation)
}

// call invokes a hashing operation and releases the returned buffer. Nonzero
// library statuses become errors; unrecognized operations select event ID hashing.
func call(
	roomVersion string,
	event []byte,
	operation int,
) (string, error) {
	version := C.CString(roomVersion)
	defer C.free(unsafe.Pointer(version))
	var out *C.uint8_t
	var outLen C.size_t
	// Never pass NULL: the ABI rejects it, and an empty input should reach the
	// library so it can report its own message.
	var empty C.uint8_t
	first := &empty
	if len(event) > 0 {
		first = (*C.uint8_t)(unsafe.Pointer(&event[0]))
	}
	var status C.int
	switch operation {
	case verifyContentHashOperation:
		status = C.rezzy_verify_content_hash(version, first, C.size_t(len(event)), &out, &outLen)
	case hashEventsOperation:
		status = C.rezzy_hash_events(version, first, C.size_t(len(event)), &out, &outLen)
	default:
		status = C.rezzy_event_id(version, first, C.size_t(len(event)), &out, &outLen)
	}
	var text string
	if out != nil {
		text = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outLen))
		C.rezzy_free(out, outLen)
	}
	if status != C.REZZY_OK {
		return "", fmt.Errorf("rezzy: %s", text)
	}
	return text, nil
}

// main reads an input file, runs the selected operation, and prints its result.
// Usage errors exit with status 2; file and hashing errors exit with status 1.
func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <event-id|verify-content-hash|hash-events> <room-version> <event.jsonl>\n", os.Args[0])
		os.Exit(2)
	}
	action, roomVersion, path := os.Args[1], os.Args[2], os.Args[3]
	event, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch action {
	case "event-id":
		id, err := EventID(roomVersion, event)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(id)
	case "verify-content-hash":
		if err := VerifyContentHash(roomVersion, event); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("content hash valid")
	case "hash-events":
		report, err := HashEventsJSONL(roomVersion, event)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(report)
	default:
		fmt.Fprintf(os.Stderr, "unknown action %q (use event-id, verify-content-hash, or hash-events)\n", action)
		os.Exit(2)
	}
}
