import socket, selectors, os
from utils import DEFAULT_PORT, PORT_FILE

sel = selectors.DefaultSelector()

def get_port():
    if os.path.exists(PORT_FILE):
        try: 
            with open(PORT_FILE, "r") as f:
                return int(f.read().strip())
        except Exception as e:
            print("[!] Warning: Could not read '{PORT_FILE}' ({e}). Using default port '{DEFAULT_PORT}'.")
    else:
        print(f"[!] Warning: '{PORT_FILE}' not found. Using default port '{DEFAULT_PORT}'.")

    return DEFAULT_PORT
    
def accept_connection(sock):
    """Handles an incoming connection from a new client."""
    conn, addr = sock.accept()
    print(f"[+] New connection from => '{addr}'")
    conn.setblocking(False)  # Make the client socket non-blocking

    # Register the client socket for READ events
    # We pass 'conn' as the data payload to easily retrieve it later
    sel.register(conn, selectors.EVENT_READ, data=handle_client)

def handle_client(conn):
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

def main():
    print("hello world!")

if __name__ == "__main__":
    main()