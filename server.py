import selectors, socket
import protocol

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
        print(f"[**] Server listening on ({self.host}:{self.port})")

        try:
            while True:
                # Block until I/O events are available
                events = self.selector.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        # Listener socket is ready -> Accept new connection
                        self._accept_connection(key.fileobj)
                    else:
                        # Established client socket is ready -> Service read/write
                        self._handle_client(key, mask)

        except KeyboardInterrupt:
            print("\n[*] Server stopping...")
        except:
            print("\n[*] Server shutting down...")
            server_sock.close()
        finally:
            self.selector.close()

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

    def _handle_client(self, key: selectors.SelectorKey, mask: int):
        """
        Routes the ready client socket to either read or write operations.
        """
        conn:socket.socket = key.fileobj
        session: ClientSession = key.data

        # socket is ready for reading incoming data
        if mask & selectors.EVENT_READ:
            self._handle_read(conn, session)

        # socket is ready for sending outgoing responses
        if mask & selectors.EVENT_WRITE:
            self._handle_write(conn, session)

    def _handle_read(self, conn:socket.socket, session: ClientSession):
        """
        Reads bytes from the client and triggers packet processing.
        """
        try:
            chunk = conn.recv(4096)
            if not chunk:
                # Empty read means the client closed the connection cleanly
                print(f"[-] Client {session.addr} disconnected.")
                self._disconnect(conn)
                return

            # Append new bytes to this client's incoming buffer
            session.in_buffer.extend(chunk)

            # Check if one or more full packets are ready to be parsed
            self._process_packets(conn, session)

        except ConnectionResetError:
            print(f"[-] Client {session.addr} suddenly dropped connection.")
            self._disconnect(conn)
        except Exception as e:
            print(f"[!] Read error from {session.addr}: {e}")
            self._disconnect(conn)

    def _handle_write(self, conn: socket.socket, session: ClientSession):
        """
        Sends pending response bytes from out_buffer over the socket.
        """
        try:
            if session.out_buffer:
                bytes_sent = conn.send(session.out_buffer)
                session.out_buffer = session.out_buffer[bytes_sent:]  # Remove sent bytes

            # If all data was transmitted, stop listening for WRITE events
            if not session.out_buffer:
                self.selector.modify(conn, selectors.EVENT_READ, data=session)

        except Exception as e:
            print(f"[!] Write error to {session.addr}: '{e}'")
            self._disconnect(conn)

    def _process_packets(self, conn: socket.socket, session: ClientSession):
        """
        Extracts complete request frames (Header + Payload) from the buffer.
        """
        while True:
            #Do we have enough bytes for the 23-byte header?
            if len(session.in_buffer) < protocol.REQ_HEADER_SIZE:
                break  # Wait for more bytes to arrive in future read events

            # Unpack header without removing it to inspect payload size
            header_bytes = bytes(session.in_buffer[:protocol.REQ_HEADER_SIZE])
            client_id, version, code, payload_size = protocol.unpack_request_header(header_bytes)

            total_packet_size = protocol.REQ_HEADER_SIZE + payload_size

            # Do we have the complete payload for this request?
            if len(session.in_buffer) < total_packet_size:
                break  # Complete packet hasn't arrived yet; keep waiting
            
            # got full packet, extract payload and consume bytes from buffer
            payload = bytes(session.in_buffer[protocol.REQ_HEADER_SIZE:total_packet_size])
            session.in_buffer = session.in_buffer[total_packet_size:]
            
            break;
            # TODO: handle payload later


    def _disconnect(self, conn: socket.socket):
        """
        Cleans up and releases socket resources.
        """
        try:
            self.selector.unregister(conn)
        except (KeyError, ValueError):
            pass
        try:
            conn.close()
        except OSError:
            pass