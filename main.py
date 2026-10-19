# Import helper settings and the Server class
from utils import load_port, LOCAL_HOST
from server import Server


def main() -> None:
    """
    Main function that starts the server application.
    """
    # Load the port number from port.info (or use the default)
    port = load_port()
    
    # Set the IP address (localhost)
    host = LOCAL_HOST
    
    # Create the Server object and start listening for connections
    Server(host=host, port=port).start()


# Run the main function
if __name__ == "__main__":
    main()