import uuid, os
import protocol
from utils import SERVER_VERSION
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# { client_id_bytes: {"name": str, "public_key": bytes, "aes_key": bytes} }
class RequestHandler:
    def __init__(self):
        self.active_clients = {}
        
    def handle(self, client_id: str, code:int, payload:bytes) -> bytes:
        try:
            if code == protocol.CODE_REQ_REGISTER:
                return self._handle_registration(payload)
            elif code == protocol.CODE_REQ_SEND_PUB_KEY:
                return self._handle_public_key(client_id, payload);
            elif code == protocol.CODE_REQ_RECONNECT:
                return self._handle_reconnect(client_id, payload);
            elif code == protocol.CODE_REQ_SEND_FILE:
                return;
            elif code == protocol.CODE_REQ_CRC_OK:
                return;
            elif code in (protocol.CODE_REQ_CRC_RETRY, protocol.CODE_REQ_CRC_FAIL):
                return;
            else:
                return;
        except Exception:
            return;

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
        new_uuid = uuid.uuid4().bytes

        self._update_active_clients(new_uuid, client_name);

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

        pub_key_der = self.active_clients[client_id]["public_key"]
        rsa_key = RSA.import_key(pub_key_der)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher.encrypt(new_aes_key)

        # Response 1605: 16-byte Client ID + 128-byte Encrypted AES key
        return protocol.pack_response(protocol.CODE_RESP_RECONNECT_SUCCESS, client_id + encrypted_aes_key, version=SERVER_VERSION)

    
    