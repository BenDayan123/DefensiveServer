import socket, selectors, os
from utils import DEFAULT_PORT, PORT_FILE

def get_port():
    if os.path.exists(PORT_FILE):
        try: 
            with open(PORT_FILE, "r") as f:
                return int(f.read().strip())
        except Exception as e:
            print("[!] Warning: Could not read {PORT_FILE} ({e}). Using default port {DEFAULT_PORT}.")
    else:
        print(f"[!] Warning: {PORT_FILE} not found. Using default port {DEFAULT_PORT}.")
        
    return DEFAULT_PORT
    


def main():
    print("hello world!")

if __name__ == "__main__":
    main()