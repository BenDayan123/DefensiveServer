import uuid, os, struct
import protocol
from utils import SERVER_VERSION
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from database import Database
import cksum

class RequestHandler:
    def __init__(self):
        self.db = Database()
        self.active_clients = self.db.load_clients()
        self.last_file_for_client = {}  # Tracks client_id -> file_name for CRC match

    def handle(self, client_id: str, code:int, payload:bytes) -> bytes | None:
        try:
            match code:
                case protocol.CODE_REQ_REGISTER:
                    return self._handle_registration(payload)
                case protocol.CODE_REQ_SEND_PUB_KEY:
                    return self._handle_public_key(client_id, payload)
                case protocol.CODE_REQ_RECONNECT:
                    return self._handle_reconnect(client_id, payload)
                case protocol.CODE_REQ_SEND_FILE:
                    return self._handle_receive_file(client_id, payload)
                case protocol.CODE_REQ_CRC_OK:
                    return self._handle_crc_ok(client_id)
                case protocol.CODE_REQ_CRC_RETRY | protocol.CODE_REQ_CRC_FAIL:
                    return self._handle_crc_abort(client_id, code)
                case _:
                    return None
        
        except Exception as e: # code = 1607
            print(f"[!] Handler error: {e}")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

    def _update_active_clients(self, client_id: bytes, name:str = None, public_key: bytes = None, aes_key: bytes = None):
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
        client_name = payload.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")

        # Check if username is already registered (Protocol requirement -> 1601)
        for client in self.active_clients.values():
            if client.get("name") == client_name:
                print(f"[-] [825] Rejected: Name '{client_name}' already exists.")
                return protocol.pack_response(protocol.CODE_RESP_REGISTER_FAIL, version=SERVER_VERSION)
            
        new_uuid = uuid.uuid4().bytes
        self._update_active_clients(new_uuid, client_name);
        self.db.add_client(new_uuid, client_name)

        print(f"[+] [825] Registered '{client_name}' -> UUID: {new_uuid.hex()}")
        return protocol.pack_response(protocol.CODE_RESP_REGISTER_SUCCESS, new_uuid, SERVER_VERSION)

    def _handle_public_key(self, client_id: bytes ,payload: bytes) -> bytes:
        """
        Handles Code 826:
        Extracts client name (255 bytes) and RSA public key (160 bytes).
        Generates a new 256-bit (32 bytes) AES symmetric key.
        Encrypts the AES key using the client's RSA public key (OAEP-SHA1).
        Returns Response 1602: Client ID (16 bytes) + Encrypted AES key (128 bytes).
        """
        if len(payload) < protocol.SIZE_CLIENT_NAME + protocol.SIZE_PUBLIC_KEY:
            print(f"[-] [826] Invalid payload size ({len(payload)} bytes). Expected at least 415 bytes.")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

        # 1. Unpack payload fields
        client_name = payload[:255].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
        public_key = payload[255:255 + 160]

        print(f"[+] [826] Received key for '{client_name}' (UUID: {client_id.hex()})")

        aes_key = os.urandom(32)
        self._update_active_clients(client_id, client_name, public_key, aes_key);
        self.db.update_client_keys(client_id, public_key=public_key, aes_key=aes_key)

        # Encrypting the AES key using the RSA public key
        try:
            rsa_key = RSA.import_key(public_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher.encrypt(aes_key)
        except Exception as e:
            print(f"[-] [826] RSA encryption failed: {e}")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

        # Response 1602: UUID (16 bits) + AES (128B)
        response_payload = client_id + encrypted_aes_key
        return protocol.pack_response(protocol.CODE_RESP_PUB_KEY_AES, response_payload, version=SERVER_VERSION)

    def _handle_reconnect(self, client_id: bytes, payload: bytes) -> bytes:
        """Handles Request 827: Generates a new AES key for recognized registered client."""
        client_name = payload[:protocol.SIZE_CLIENT_NAME].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")

        # Validate that client exists and has a registered public key
        if client_id not in self.active_clients or not self.active_clients[client_id]["public_key"]:
            print(f"[-] [827] Rejected: Client {client_id.hex()} not recognized.")
            return protocol.pack_response(protocol.CODE_RESP_RECONNECT_FAIL, client_id, version=SERVER_VERSION)

        print(f"[+] [827] Re-authenticating '{client_name}' (UUID: {client_id.hex()})")

        # Generate a fresh AES-256 key for this new session
        new_aes_key = os.urandom(32)
        self.active_clients[client_id]["aes_key"] = new_aes_key
        self.db.update_client_keys(client_id, aes_key=new_aes_key)

        pub_key_der = self.active_clients[client_id]["public_key"]
        rsa_key = RSA.import_key(pub_key_der)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher.encrypt(new_aes_key)

        # Response 1605: 16-byte Client ID + 128-byte Encrypted AES key
        return protocol.pack_response(protocol.CODE_RESP_RECONNECT_SUCCESS, client_id + encrypted_aes_key, version=SERVER_VERSION)

    def _handle_receive_file(self, client_id: bytes, payload: bytes) -> bytes:
        """
        Handles Request 828:
        Decrypts the uploaded file, saves it to disk, and computes the POSIX CRC.
        """
        # Metadata format: Content Size (4B), Orig Size (4B), Packet No (2B), Total Packets (2B), File Name (255B)
        meta_format = "<I I H H 255s"
        meta_size = struct.calcsize(meta_format)

        if len(payload) < meta_size:
            print("[-] [828] Payload smaller than metadata header.")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

        content_size, orig_size, _, _, raw_name = struct.unpack(meta_format, payload[:meta_size])
        file_name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        encrypted_data = payload[meta_size : meta_size + content_size]

        if client_id not in self.active_clients or not self.active_clients[client_id]["aes_key"]:
            print(f"[-] [828] Client {client_id.hex()} has no active AES session.")
            return protocol.pack_response(protocol.CODE_RESP_GENERAL_ERROR, version=SERVER_VERSION)

        aes_key = self.active_clients[client_id]["aes_key"]

        # Decrypt content using AES-256-CBC (IV is 16 zeroes)
        iv = b"\x00" * 16
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_content = decrypted_padded[:orig_size]

        # Save received file to disk in a dedicated directory
        upload_dir = "received_files"
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, os.path.basename(file_name))
        with open(file_path, "wb") as f:
            f.write(decrypted_content)

        # Record file metadata in files table
        self.db.record_file(client_id, file_name, file_path, verified=False)
        self.last_file_for_client[client_id] = file_name

        # =========================================================================
        # Calculate Checksum using memcrc from cksum.py
        # =========================================================================
        crc_val = cksum.memcrc(decrypted_content)

        print(f"[+] [828] Saved '{file_name}' ({orig_size} bytes).")
        print(f"    Calculated POSIX CRC: {crc_val}")

        # Pack Response 1603:
        # Layout: Client ID (16B) + Content Size (4B) + File Name (255B) + Checksum (4B) = 279B
        name_padded = file_name.encode("utf-8")[:254].ljust(protocol.SIZE_CLIENT_NAME, b"\x00")
        resp_payload = struct.pack(
            f"<{protocol.SIZE_CLIENT_ID}s I {protocol.SIZE_CLIENT_NAME}s I",
            client_id,
            orig_size,
            name_padded,
            crc_val
        )

        return protocol.pack_response(protocol.CODE_RESP_FILE_CRC, resp_payload, version=SERVER_VERSION)

    def _handle_crc_ok(self, client_id: bytes) -> bytes:
        """Handles Request 900: Client confirmed CRC match."""
        file_name = self.last_file_for_client.get(client_id)
        if file_name:
            self.db.set_file_verified(client_id, file_name)
            
        print(f"[+] [900] Client {client_id.hex()} verified file successfully.")
        return protocol.pack_response(protocol.CODE_RESP_MSG_CONFIRM, client_id, version=SERVER_VERSION)

    def _handle_crc_abort(self, client_id: bytes, code: int) -> bytes:
        """Handles Request 901/902."""
        if code == protocol.CODE_REQ_CRC_RETRY:
            print(f"[!] [901] Client {client_id.hex()} requested retry.")
        else: print(f"[!] [{code}] Client {client_id.hex()} reported CRC failure.")
        return protocol.pack_response(protocol.CODE_RESP_MSG_CONFIRM, client_id, version=SERVER_VERSION)