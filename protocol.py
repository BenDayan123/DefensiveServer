import struct
from typing import Tuple

# ==========================================
# Protocol Field Sizes (Bytes)
# ==========================================
SIZE_CLIENT_ID = 16          # Unique client ID length (UUID)
SIZE_CLIENT_NAME = 255       # Client name maximum length (padded with null bytes)
SIZE_PUBLIC_KEY = 160        # RSA-1024 public key length
SIZE_AES_KEY_ENCRYPTED = 128 # AES key encrypted with RSA length
SIZE_FILE_CONTENT_META = 4   # Size of the encrypted file content field
SIZE_FILE_ORIG_META = 4      # Size of the original file size field
SIZE_PACKET_NUM = 2          # Packet number field size
SIZE_TOTAL_PACKETS = 2       # Total packets count field size
SIZE_CKSUM = 4               # Checksum (CRC) field size

# ==========================================
# Protocol Headers
# ==========================================

# Request Header: Client ID (16B), Version (1B), Code (2B), Payload Size (4B) = 23 Bytes
REQ_HEADER_FORMAT = "<16s B H I"
REQ_HEADER_SIZE = struct.calcsize(REQ_HEADER_FORMAT)

# Response Header: Version (1B), Code (2B), Payload Size (4B) = 7 Bytes
RESP_HEADER_FORMAT = "<B H I"
RESP_HEADER_SIZE = struct.calcsize(RESP_HEADER_FORMAT)

# ==========================================
# Protocol Request Codes (Client -> Server)
# ==========================================

CODE_REQ_REGISTER = 825     # Request to register a new user
CODE_REQ_SEND_PUB_KEY = 826 # Request to send client's public key
CODE_REQ_RECONNECT = 827    # Request to reconnect an existing client
CODE_REQ_SEND_FILE = 828    # Request to upload an encrypted file
CODE_REQ_CRC_OK = 900       # Client confirms the CRC checksum matches
CODE_REQ_CRC_RETRY = 901    # Client asks to retry sending the file
CODE_REQ_CRC_FAIL = 902     # Client reports CRC failed after retries

# ==========================================
# Protocol Response Codes (Server -> Client)
# ==========================================
CODE_RESP_REGISTER_SUCCESS = 1600   # Registration succeeded
CODE_RESP_REGISTER_FAIL = 1601      # Registration failed (user already exists)
CODE_RESP_PUB_KEY_AES = 1602        # Returns the encrypted AES key to client
CODE_RESP_FILE_CRC = 1603           # Returns the calculated file CRC checksum
CODE_RESP_MSG_CONFIRM = 1604        # General confirmation message (CRC OK / abort)
CODE_RESP_RECONNECT_SUCCESS = 1605  # Reconnect approved, sends new AES key
CODE_RESP_RECONNECT_FAIL = 1606     # Reconnect denied (unknown client)
CODE_RESP_GENERAL_ERROR = 1607      # Server error response

# ============================================================================
# Protocol Helper Functions
# ============================================================================

def unpack_request_header(header_bytes: bytes) -> Tuple[bytes, int, int, int]:
    """
    Takes 23 raw bytes and unpacks them into:
    (client_id, version, request_code, payload_size).
    """
    return struct.unpack(REQ_HEADER_FORMAT, header_bytes)


def pack_response(code: int, payload: bytes = b"", version: int = 3) -> bytes:
    """
    Builds a complete binary response packet:
    7-byte header (version, code, payload length) + payload data.
    """
    # Create the 7-byte response header
    header = struct.pack(RESP_HEADER_FORMAT, version, code, len(payload))
    # Combine header and payload into one byte string
    return header + payload