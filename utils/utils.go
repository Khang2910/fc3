package utils

/*
#include <string.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"unsafe"
)

func EncodeDump(buffer unsafe.Pointer, value string, size int) {
	if size <= 0 {
		return
	}

	max := size - 1
	encoded := base64.StdEncoding.EncodeToString([]byte(value))

	if max > len(encoded) {
		max = len(encoded)
	}

	for i := 0; i < max; i++ {
		*(*byte)(unsafe.Pointer(uintptr(buffer) + uintptr(i))) = encoded[i]
	}

	*(*byte)(unsafe.Pointer(uintptr(buffer) + uintptr(max))) = 0
}

