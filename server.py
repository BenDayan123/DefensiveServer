import selectors, socket

class ClientSession:
    """
    Holds the temporary connection state for a single connected client.
    Because TCP delivers data in fragments, this class acts as a buffer
    so we can reassemble full packets before processing them.
    """
    def __init__(self, conn: socket.socket, addr: tuple):
        self.conn = conn
        self.addr = addr
        self.in_buffer = bytearray()      # Accumulates incoming raw bytes
        self.out_buffer = bytearray()     # Holds response bytes queued for sending

class Server:
    def __init__(self, host:str, port: int):
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()

    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Allow immediate reuse of the local address/port
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen()
        server_sock.setblocking(False) # Never block the server on operations

        # Register the listening socket to handle new connections
        self.selector.register(server_sock, selectors.EVENT_READ, data=None)
        print(f"[*] Server listening on ({self.host}:{self.port})...")

        try:
            while True:
                # Block until I/O events are available
                evenets = self.selector.select(timeout=None)
                for key, mask in evenets:
                    if key.data is None:
                        # Listener socket is ready -> Accept new connection
                        self._accept_connection(key.fileobj)
                    else 
                        # Established client socket is ready -> Service read/write
                        self._service_client(key, mask)

        except:
            print("\n[*] Server shutting down...")
            self.selector.close()
            server_sock.close()

    def _accept_connection(self, sock: socket.socket):
        """
        Accepts a new incoming TCP connection and attaches a ClientSession to it.
        """
        conn, addr = sock.accept()
        conn.setblocking(False) # Make client non-blocking as well
        print(f"[+] New connection from => '{addr}'")

        session = ClientSession(conn,addr)
        # Register the client socket for READ events
        self.selector.register(conn, selectors.EVENT_READ, data=session)

    def _service_client(self, key: selectors.SelectorKey, mask: int):
        """
        Routes the ready client socket to either read or write operations.
        """
        conn:socket.socket = key.fileobj
        session: ClientSession = key.data



    def _close_connection(self, conn: socket.socket):
        """
        Cleans up and releases socket resources safely.
        """
        try:
            self.selector.unregister(conn)
        except (KeyError, ValueError):
            pass
        try:
            conn.close()
        except OSError:
            pass