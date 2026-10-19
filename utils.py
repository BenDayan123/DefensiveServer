import os

# ============================================================================
# Global Configuration Variables
# ============================================================================

# The default port number to use if port.info cannot be read
DEFAULT_PORT = 1369

# The file name where the listening port is saved
PORT_FILE = "port.info"

# The local IP address where the server runs
LOCAL_HOST = "127.0.0.1"

# The protocol version number supported by this server
SERVER_VERSION = 3


# ============================================================================
# Functions
# ============================================================================

def load_port(file: str = PORT_FILE) -> int:
    """
    Reads the port number from a text file.
    If the file is missing or invalid, it returns the default port.
    """
    # Check if the port file exists on disk
    if os.path.exists(file):
        try:
            # Open the file, read the text, and convert it to an integer
            with open(file, "r") as f:
                return int(f.read().strip())
        except Exception as e:
            # If reading or converting fails, print a warning
            print(f"[!] Warning: Could not read '{file}' ({e}). Using default port '{DEFAULT_PORT}'.")
    else:
        # If the file does not exist, print a warning
        print(f"[!] Warning: '{file}' not found. Using default port '{DEFAULT_PORT}'.")

    # Return the fallback default port
    return DEFAULT_PORT