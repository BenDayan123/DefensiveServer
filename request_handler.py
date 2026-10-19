import uuid
import os
import struct
import protocol
from utils import SERVER_VERSION
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from database import Database
import cksum

# Directory where uploaded files are saved
upload_dir = "received_files"


class RequestHandler:
    """
    Processes incoming client requests and generates appropriate protocol responses.
    """

    def __init__(self):
        """
        Initializes database access and in-memory caches.
        """
        # Database instance
        self.db = Database()
        
        # In-memory dictionary of registered clients loaded from DB
        self.active_clients = self.db.load_clients()
        
        # Dictionary mapping client_id to the most recent file name for CRC checks
        self.last_file_for_client = {}

    def handle(self, client_id: bytes, code: int, payload: bytes) -> bytes | None:
        """
        Routes the request to the correct handler method based on the request code.
        """
        try:
            match code:
                case protocol.CODE_REQ_REGISTER:  # Code 825: Register client
                    return self._handle_registration(payload)

                case protocol.CODE_REQ_SEND_PUB_KEY:  # Code 826: Receive public key
                    return self._handle_public_key(client_id, payload)

                case protocol.CODE_REQ_RECONNECT:  # Code 827: Reconnect existing client
                    return self._handle_reconnect(client_id, payload)

                case protocol.CODE_REQ_SEND_FILE:  # Code 828: Receive encrypted file
                    return self._handle_receive_file(client_id, payload)

                case protocol.CODE_REQ_CRC_OK:  # Code 900: Client confirmed CRC is good
                    return self._handle_crc_ok(client_id)

                case protocol.CODE_REQ_CRC_RETRY | protocol.CODE_REQ_CRC_FAIL:  # Code 901 or 902: CRC retry/failure
                    return self._handle_crc_abort(client_id, code)

                case _:  # Unknown code
                    return None

        except Exception as e:
            # On unexpected error, return response code 1607 (General Error)
            print(f"[!] Handler error: {e}")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

    def _update_active_clients(self, client_id: bytes, name: str = None, public_key: bytes = None, aes_key: bytes = None):
        """
        Updates or adds client information in the in-memory dictionary.
        """
        if client_id in self.active_clients:
            self.active_clients[client_id]["public_key"] = public_key
            self.active_clients[client_id]["aes_key"] = aes_key
        else:
            self.active_clients[client_id] = {
                "name": name,
                "public_key": public_key,
                "aes_key": aes_key
            }

    def _handle_registration(self, payload: bytes) -> bytes:
        """
        Handles Code 825:
        Registers a new client name and assigns a new 16-byte UUID.
        """
        # Read the client name up to the first null byte
        client_name = payload.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")

        # Reject if the username is already registered (Response 1601)
        for client in self.active_clients.values():
            if client.get("name") == client_name:
                print(f"[-] [825] Rejected: Name '{client_name}' already exists.")
                return protocol.pack_response(protocol.CODE_RESP_REGISTER_FAIL, version=SERVER_VERSION)

        # Generate a new unique 16-byte ID
        new_uuid = uuid.uuid4().bytes

        # Save to memory and database
        self._update_active_clients(new_uuid, client_name)
        self.db.add_client(new_uuid, client_name)

        print(f"[+] [825] Registered '{client_name}' -> UUID: {new_uuid.hex()}")
        # Response 1600: Registration Success + new 16-byte UUID
        return protocol.pack_response(protocol.CODE_RESP_REGISTER_SUCCESS, new_uuid, SERVER_VERSION)

    def _handle_public_key(self, client_id: bytes, payload: bytes) -> bytes:
        """
        Handles Code 826:
        Receives client's RSA public key, generates an AES-256 key,
        encrypts the AES key using the RSA public key, and sends it back.
        """
        # Validate that payload has at least name (255B) + public key (160B)
        if len(payload) < protocol.SIZE_CLIENT_NAME + protocol.SIZE_PUBLIC_KEY:
            print(f"[-] [826] Invalid payload size ({len(payload)} bytes). Expected at least 415 bytes.")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

        # Extract client name (255 bytes) and RSA public key (160 bytes)
        client_name = payload[:255].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
        public_key = payload[255:255 + 160]

        print(f"[+] [826] Received key for '{client_name}' (UUID: {client_id.hex()})")

        # Generate a new random 32-byte (256-bit) AES key
        aes_key = os.urandom(32)

        # Save keys to memory and database
        self._update_active_clients(client_id, client_name, public_key, aes_key)
        self.db.update_client_keys(client_id, public_key=public_key, aes_key=aes_key)

        # Encrypt the AES key with the client's RSA public key
        try:
            rsa_key = RSA.import_key(public_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher.encrypt(aes_key)
        except Exception as e:
            print(f"[-] [826] RSA encryption failed: {e}")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

        # Response 1602: Client ID (16B) + Encrypted AES key (128B)
        response_payload = client_id + encrypted_aes_key
        return protocol.pack_response(protocol.CODE_RESP_PUB_KEY_AES, response_payload, version=SERVER_VERSION)

    def _handle_reconnect(self, client_id: bytes, payload: bytes) -> bytes:
        """
        Handles Code 827:
        Re-authenticates a registered client and sends a new encrypted AES key.
        """
        # Extract client name from the payload
        client_name = payload[:protocol.SIZE_CLIENT_NAME].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")

        # Check if the client exists and has a saved public key
        if client_id not in self.active_clients or not self.active_clients[client_id]["public_key"]:
            print(f"[-] [827] Rejected: Client {client_id.hex()} not recognized.")
            return protocol.pack_response(protocol.CODE_RESP_RECONNECT_FAIL, client_id, version=SERVER_VERSION)

        pub_key_der = self.active_clients[client_id]["public_key"]

        # Encrypt a new AES key for this session
        try:
            rsa_key = RSA.import_key(pub_key_der)
            cipher = PKCS1_OAEP.new(rsa_key)
            new_aes_key = os.urandom(32)
            encrypted_aes_key = cipher.encrypt(new_aes_key)
        except Exception as e:
            print(f"[-] [827] Reconnect RSA encryption failed: {e}. Rejecting reconnect.")
            return protocol.pack_response(protocol.CODE_RESP_RECONNECT_FAIL, client_id, version=SERVER_VERSION)

        print(f"[+] [827] Re-authenticating '{client_name}' (UUID: {client_id.hex()})")

        # Update the AES key in memory and database
        self.active_clients[client_id]["aes_key"] = new_aes_key
        self.db.update_client_keys(client_id, aes_key=new_aes_key)

        # Response 1605: Client ID (16B) + Encrypted AES key (128B)
        return protocol.pack_response(protocol.CODE_RESP_RECONNECT_SUCCESS, client_id + encrypted_aes_key, version=SERVER_VERSION)

    def _handle_receive_file(self, client_id: bytes, payload: bytes) -> bytes:
        """
        Handles Code 828:
        Decrypts an incoming file using AES-CBC, saves it to disk, and computes the CRC checksum.
        """
        # Metadata header format: Content Size (4B), Orig Size (4B), Packet # (2B), Total Packets (2B), File Name (255B)
        meta_format = "<I I H H 255s"
        meta_size = struct.calcsize(meta_format)

        # Check if payload has at least the full metadata header
        if len(payload) < meta_size:
            print("[-] [828] Payload smaller than metadata header.")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

        # Unpack the file metadata
        content_size, orig_size, _, _, raw_name = struct.unpack(meta_format, payload[:meta_size])
        file_name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        encrypted_data = payload[meta_size: meta_size + content_size]

        # Make sure the client has an active AES key
        if client_id not in self.active_clients or not self.active_clients[client_id]["aes_key"]:
            print(f"[-] [828] Client {client_id.hex()} has no active AES session.")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

        aes_key = self.active_clients[client_id]["aes_key"]

        # Decrypt file data using AES-256-CBC with an IV of 16 zeroes
        iv = b"\x00" * 16
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        # Trim padding to restore original file size
        decrypted_content = decrypted_padded[:orig_size]

        # Create output folder if it doesn't exist
        os.makedirs(upload_dir, exist_ok=True)
        
        # Build a safe and unique file name on disk
        safe_name = os.path.basename(file_name)
        file_unique_id = uuid.uuid4().hex[:8]
        unique_disk_name = f"{client_id.hex()}_{file_unique_id}_{safe_name}"
        file_path = os.path.join(upload_dir, unique_disk_name)

        # Save decrypted file to disk
        with open(file_path, "wb") as f:
            f.write(decrypted_content)

        # Record file details in database
        self.db.record_file(client_id, safe_name, file_path, verified=False)
        self.last_file_for_client[client_id] = safe_name

        # Calculate the POSIX CRC-32 checksum of the decrypted content
        crc_val = cksum.memcrc(decrypted_content)

        print(f"[+] [828] Saved '{file_name}' ({orig_size} bytes).")
        print(f"    Calculated POSIX CRC: {crc_val}")

        # Pack Response 1603: Client ID (16B) + Content Size (4B) + File Name (255B) + Checksum (4B)
        name_padded = file_name.encode("utf-8")[:254].ljust(protocol.SIZE_CLIENT_NAME, b"\x00")
        resp_payload = struct.pack(
            f"<{protocol.SIZE_CLIENT_ID}s I {protocol.SIZE_CLIENT_NAME}s I",
            client_id,
            content_size,
            name_padded,
            crc_val
        )

        return protocol.pack_response(protocol.CODE_RESP_FILE_CRC, resp_payload, version=SERVER_VERSION)

    def _handle_crc_ok(self, client_id: bytes) -> bytes:
        """
        Handles Code 900:
        Client confirms the checksum matched. Marks the file as verified.
        """
        file_name = self.last_file_for_client.get(client_id)
        if file_name:
            self.db.set_file_verified(client_id, file_name)

        print(f"[+] [900] Client {client_id.hex()} verified file successfully.")
        # Response 1604: Confirmation message with client ID
        return protocol.pack_response(protocol.CODE_RESP_MSG_CONFIRM, client_id, version=SERVER_VERSION)

    def _handle_crc_abort(self, client_id: bytes, code: int) -> bytes:
        """
        Handles Code 901 (retry) and 902 (crc failed).
        Acknowledge with confirmation code 1604.
        """
        if code == protocol.CODE_REQ_CRC_RETRY:
            print(f"[!] [901] Client {client_id.hex()} requested retry.")
        else:
            print(f"[!] [{code}] Client {client_id.hex()} reported CRC failure.")
        return protocol.pack_response(protocol.CODE_RESP_MSG_CONFIRM, client_id, version=SERVER_VERSION)