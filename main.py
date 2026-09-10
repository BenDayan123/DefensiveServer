from utils import load_port, LOCAL_HOST
from server import Server

def main() -> None:
    """
    Server entry point: sets up socket options, binds, and runs the event loop.
    """
    port = load_port()
    host = LOCAL_HOST
    Server(host=host, port=port).start()

if __name__ == "__main__":
    main()