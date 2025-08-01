//go:build windows
package main

/*
#include <string.h>
#include <stdlib.h>
*/
import "C"

import (
	"os"
	"unsafe"
)

import (
	"github.com/fc3/utils"
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
	utils.EncodeDump(unsafe.Pointer(output), result, int(size))
}

//export read
func read(output *C.char, size C.int, file *C.char, _ *C.char) {
	path := C.GoString(file)
	data, err := os.ReadFile(path)
	result := ""
	if err != nil {
		result = "error: " + err.Error()
	} else {
		result = string(data)
	}

	utils.EncodeDump(unsafe.Pointer(output), result, int(size))
}

func main() {}
