import selectors
import socket
import time
import protocol
from request_handler import RequestHandler

# Maximum idle time in seconds before a client connection is closed (5 minutes)
CLIENT_TIMEOUT_SECONDS = 300


class ClientSession:
    """
    Stores connection state and data buffers for a single connected client.
    """

    def __init__(self, conn: socket.socket, addr: tuple):
        # The client socket object
        self.conn = conn
        
        # The client remote IP address and port
        self.addr = addr
        
        # Buffer that collects incoming raw bytes until a full packet is ready
        self.in_buffer = bytearray()
        
        # Buffer that holds outgoing response bytes waiting to be sent
        self.out_buffer = bytearray()
        
        # Timestamp of the last time this client was active
        self.last_active = time.time()


class Server:
    """
    Non-blocking TCP server that uses selectors to handle multiple clients concurrently.
    """

    def __init__(self, host: str, port: int):
        """
        Initializes server network settings, selector, and request handler.
        """
        self.host = host                        # Server IP address
        self.port = port                        # Server listening port
        self.selector = selectors.DefaultSelector() # I/O multiplexer
        self.handler = RequestHandler()         # Request logic processor

    def start(self):
        """
        Creates the main server socket, binds it, and runs the event loop.
        """
        # Create a standard TCP/IP socket
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Allow immediate reuse of the address and port after restart
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind socket to the specified host and port
        server_sock.bind((self.host, self.port))
        
        # Start listening for incoming connections
        server_sock.listen()
        
        # Set socket to non-blocking mode
        server_sock.setblocking(False)

        # Register the listening socket with the selector for incoming READ events
        self.selector.register(server_sock, selectors.EVENT_READ, data=None)
        print(f"[**] Server listening on ({self.host}:{self.port})")

        # Main server event loop
        try:
            while True:
                # Wait for sockets that are ready for reading or writing (1-second timeout)
                events = self.selector.select(timeout=1.0)
                
                for key, mask in events:
                    if key.data is None:
                        # Listener socket is ready -> accept a new connection
                        self._accept_connection(key.fileobj)
                    else:
                        # Existing client socket is ready -> read or write
                        self._handle_client(key, mask)
                
                # Disconnect any clients that stayed idle too long
                self._check_timeouts()

        except KeyboardInterrupt:
            print("\n[*] Server stopping...")
        except Exception:
            print("\n[*] Server shutting down...")
            server_sock.close()
        finally:
            self.selector.close()

    def _check_timeouts(self):
        """
        Checks all connected clients and closes any that have exceeded the timeout limit.
        """
        now = time.time()
        for key in list(self.selector.get_map().values()):
            session: ClientSession = key.data
            # Skip the main listening socket (whose key.data is None)
            if session is not None:
                if abs(now - session.last_active) > CLIENT_TIMEOUT_SECONDS:
                    print(f"[-] Client {session.addr} timed out (inactive for {CLIENT_TIMEOUT_SECONDS / 60} minutes). Closing connection.")
                    self._disconnect(session.conn)

    def _accept_connection(self, sock: socket.socket):
        """
        Accepts a new incoming TCP connection and creates a ClientSession for it.
        """
        conn, addr = sock.accept()
        conn.setblocking(False)  # Make the client socket non-blocking
        print(f"[+] New connection from => '{addr}'")

        # Create a new session tracker for this client
        session = ClientSession(conn, addr)
        
        # Register the client socket for READ events
        self.selector.register(conn, selectors.EVENT_READ, data=session)

    def _handle_client(self, key: selectors.SelectorKey, mask: int):
        """
        Directs client socket activity to either read or write functions.
        """
        conn: socket.socket = key.fileobj
        session: ClientSession = key.data

        # Client socket has data available to read
        if mask & selectors.EVENT_READ:
            self._handle_read(conn, session)

        # Client socket is ready to receive outgoing data
        if mask & selectors.EVENT_WRITE:
            self._handle_write(conn, session)

    def _handle_read(self, conn: socket.socket, session: ClientSession):
        """
        Reads raw bytes from the client and appends them to the client's buffer.
        """
        try:
            chunk = conn.recv(4096)
            if not chunk:
                # Client closed the connection
                return

            # Update the last active time and append new data to buffer
            session.last_active = time.time()
            session.in_buffer.extend(chunk)

            # Check if there are complete packets to parse
            self._process_packets(conn, session)

        except ConnectionResetError:
            print(f"[-] Client {session.addr} suddenly dropped connection.")
            self._disconnect(conn)
        except Exception as e:
            print(f"[!] Read error from {session.addr}: {e}")
            self._disconnect(conn)

    def _handle_write(self, conn: socket.socket, session: ClientSession):
        """
        Sends pending response bytes from out_buffer to the client socket.
        """
        try:
            if session.out_buffer:
                # Send buffered bytes over the network
                bytes_sent = conn.send(session.out_buffer)
                # Remove sent bytes from the buffer
                session.out_buffer = session.out_buffer[bytes_sent:]

            # If all data was sent, switch back to listening only for READ events
            if not session.out_buffer:
                self.selector.modify(conn, selectors.EVENT_READ, data=session)

        except Exception as e:
            print(f"[!] Write error to {session.addr}: '{e}'")
            self._disconnect(conn)

    def _process_packets(self, conn: socket.socket, session: ClientSession):
        """
        Loops through the incoming buffer, unpacks full request packets,
        and generates responses.
        """
        while True:
            # Step 1: Make sure we have at least 23 bytes for the request header
            if len(session.in_buffer) < protocol.REQ_HEADER_SIZE:
                break  # Not enough data yet; wait for more reads

            # Step 2: Read header fields to find the payload size
            header_bytes = bytes(session.in_buffer[:protocol.REQ_HEADER_SIZE])
            client_id, version, code, payload_size = protocol.unpack_request_header(header_bytes)

            total_packet_size = protocol.REQ_HEADER_SIZE + payload_size

            # Step 3: Check if the complete payload has arrived
            if len(session.in_buffer) < total_packet_size:
                break  # Packet is still incomplete; wait for more data

            # Step 4: Extract the payload and remove the packet from the incoming buffer
            payload = bytes(session.in_buffer[protocol.REQ_HEADER_SIZE:total_packet_size])
            session.in_buffer = session.in_buffer[total_packet_size:]

            # Step 5: Process the request and generate a response
            response = self.handler.handle(client_id, code, payload)

            # Step 6: Queue the response in out_buffer and enable WRITE event
            if response:
                session.out_buffer.extend(response)
                self.selector.modify(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=session)

    def _disconnect(self, conn: socket.socket):
        """
        Unregisters the socket from the selector and safely closes the connection.
        """
        try:
            self.selector.unregister(conn)
        except (KeyError, ValueError):
            pass
        try:
            conn.close()
        except OSError:
            pass