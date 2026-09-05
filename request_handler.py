import uuid
import protocol
from utils import SERVER_VERSION

class RequestHandler:
    @staticmethod
    def handle(client_id: str, code:int, payload:bytes) -> bytes:
        try:
            if code == protocol.CODE_REQ_REGISTER:
                return RequestHandler._handle_registration(payload)
            elif code == protocol.CODE_REQ_SEND_PUB_KEY:
                return;
            elif code == protocol.CODE_REQ_RECONNECT:
                return;
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

    @staticmethod
    def _handle_registration(payload: bytes) -> bytes:
        name = payload.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
        new_id = uuid.uuid4()
        return protocol.pack_response(protocol.CODE_RESP_REGISTER_SUCCESS, new_id.bytes, SERVER_VERSION)
