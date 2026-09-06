import struct
from typing import Tuple

# ==========================================
# Protocol Field Sizes (Bytes)
# ==========================================
SIZE_CLIENT_ID = 16         # Client UUID size
SIZE_CLIENT_NAME = 255      # Client Name padded length
SIZE_PUBLIC_KEY = 160       # RSA-1024 Public Key (DER format) size
SIZE_AES_KEY_ENCRYPTED = 128 # RSA-encrypted AES key size
SIZE_FILE_CONTENT_META = 4  # Content size field size
SIZE_FILE_ORIG_META = 4     # Original file size field size
SIZE_PACKET_NUM = 2         # Packet number field size
SIZE_TOTAL_PACKETS = 2      # Total packets field size
SIZE_CKSUM = 4              # CRC checksum field size

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
CODE_REQ_REGISTER = 825
CODE_REQ_SEND_PUB_KEY = 826
CODE_REQ_RECONNECT = 827
CODE_REQ_SEND_FILE = 828
CODE_REQ_CRC_OK = 900
CODE_REQ_CRC_RETRY = 901
CODE_REQ_CRC_FAIL = 902

# ==========================================
# Protocol Response Codes (Server -> Client)
# ==========================================
CODE_RESP_REGISTER_SUCCESS = 1600
CODE_RESP_REGISTER_FAIL = 1601
CODE_RESP_PUB_KEY_AES = 1602
CODE_RESP_FILE_CRC = 1603
CODE_RESP_MSG_CONFIRM = 1604
CODE_RESP_RECONNECT_SUCCESS = 1605
CODE_RESP_RECONNECT_FAIL = 1606
CODE_RESP_GENERAL_ERROR = 1607

# ==========================================
# Utility Functions
# ==========================================
def unpack_request_header(header_bytes: bytes) -> Tuple[bytes, int, int, int]:
    return struct.unpack(REQ_HEADER_FORMAT, header_bytes)

def pack_response(code: int, payload: bytes = b"", version: int = 3) -> bytes:
    header = struct.pack(RESP_HEADER_FORMAT, version, code, len(payload))
    return header + payload