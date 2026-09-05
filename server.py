import selectors, socket
from typing import List

class Server:
    def __init__(self, host:str, port: int):
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()
        self.clients: List[socket.socket] = {}
    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Allow immediate reuse of the local address/port
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen()
        server_sock.setblocking(False)

        # Register the listening socket to handle new connections
        self.selector.register(server_sock, selectors.EVENT_READ, data=None)
        print(f"[*] Server listening on ({self.host}:{self.port})...")

        try:
            while True:
                # Block until I/O events are available
                evenets = self.selector.select(timeout=None)
                for key, mask in evenets:
                    # The listening socket is ready, pass the raw socket object to callback function ('accept_connection')
                    callback = key.data
                    callback(key.fileobj)
        except:
            print("\n[*] Server shutting down...")
            self.selector.close()
            server_sock.close()