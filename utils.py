import os

DEFAULT_PORT = 1369
PORT_FILE = "port.info"
LOCAL_HOST = "127.0.0.1"
SERVER_VERSION = 3


def load_port(file:str = PORT_FILE) -> int:
    """Reads port from file or falls back to default safely."""
    if os.path.exists(file):
        try: 
            with open(file, "r") as f:
                return int(f.read().strip())
        except Exception as e:
            print(f"[!] Warning: Could not read '{file}' ({e}). Using default port '{DEFAULT_PORT}'.")
    else:
        print(f"[!] Warning: '{file}' not found. Using default port '{DEFAULT_PORT}'.")

    return DEFAULT_PORT