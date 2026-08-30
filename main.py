import socket, selectors, os
from utils import DEFAULT_PORT, PORT_FILE, LOCAL_HOST

sel = selectors.DefaultSelector()

def get_port() -> int:
    if os.path.exists(PORT_FILE):
        try: 
            with open(PORT_FILE, "r") as f:
                return int(f.read().strip())
        except Exception as e:
            print("[!] Warning: Could not read '{PORT_FILE}' ({e}). Using default port '{DEFAULT_PORT}'.")
    else:
        print(f"[!] Warning: '{PORT_FILE}' not found. Using default port '{DEFAULT_PORT}'.")

    return DEFAULT_PORT
    
def accept_connection(sock) -> None:
    """Handles an incoming connection from a new client."""
    conn, addr = sock.accept()
    print(f"[+] New connection from => '{addr}'")
    conn.setblocking(False)  # Make the client socket non-blocking

    # Register the client socket for READ events
    # We pass 'conn' as the data payload to easily retrieve it later
    sel.register(conn, selectors.EVENT_READ, data=handle_client)

def handle_client(conn) -> None:
    """Handles readable/writable events on an established client socket."""
    try:
        data = conn.recv(1024)
        if data:
            print(f"[>] Received {len(data)} bytes from client.")

            # Send response back to the client
            response = b"Connection verified"
            conn.sendall(response)
            print(f"[<] Sent {len(response)} bytes back to client.")
        else:
            # An empty read shows socket closure by the client
            print("[-] Client disconnected gracefully.")
            sel.unregister(conn)
            conn.close()

    except ConnectionResetError:
        print("[-] Client connection suddenly reset.")
        sel.unregister(conn)
        conn.close()
    except Exception as e:
        print(f"[!] Error occurred while handling client: '{e}'")
        sel.unregister(conn)
        conn.close()

def main() -> None:
    """
    Server entry point: sets up socket options, binds, and runs the event loop.
    """
    port = get_port()
    host = LOCAL_HOST
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow immediate reuse of the local address/port
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen()
    server_sock.setblocking(False)

    # Register the listening socket to handle new connections
    sel.register(server_sock, selectors.EVENT_READ, data=accept_connection)
    print(f"[*] Server listening on ({host}:{port})...")

    try:
        while True:
            # Block until I/O events are available
            evenets = sel.select(timeout=None)
            for key, mask in evenets:
                # The listening socket is ready, pass the raw socket object to callback function ('accept_connection')
                callback = key.data
                callback(key.fileobj)
    except:
        print("\n[*] Server shutting down...")
        sel.close()
        server_sock.close()


if __name__ == "__main__":
    main()