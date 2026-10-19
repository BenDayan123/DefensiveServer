import sqlite3
from datetime import datetime

# Name of the SQLite database file on disk
DB_FILE = "defensive.db"

class Database:
    """
    Handles all database operations for clients and uploaded files.
    """

    def __init__(self, db_file: str = DB_FILE):
        """
        Connects to the SQLite database and creates tables if they do not exist.
        """
        # Connection object to the SQLite database file
        self.conn = sqlite3.connect(db_file)
        # Create necessary tables
        self._create_tables()

    def _create_tables(self):
        """
        Creates 'clients' and 'files' tables if they are missing.
        """
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    ID BLOB PRIMARY KEY,
                    Name TEXT,
                    PublicKey BLOB,
                    LastSeen DATETIME,
                    AES BLOB
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    ID BLOB,
                    FileName TEXT,
                    PathName TEXT,
                    Verified BOOLEAN,
                    PRIMARY KEY (ID, FileName)
                )
            """)

    def load_clients(self) -> dict:
        """
        Loads all existing clients from the database into memory when the server boots.
        Returns a dictionary keyed by client_id.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT ID, Name, PublicKey, AES FROM clients")
        
        # Dictionary to store client data in memory
        clients = {}
        for row in cursor.fetchall():
            client_id, name, pub_key, aes_key = row
            clients[client_id] = {
                "name": name,
                "public_key": pub_key,
                "aes_key": aes_key
            }
        return clients

    def add_client(self, client_id: bytes, name: str):
        """
        Inserts a new client with the current time as LastSeen.
        """
        # Current date and time formatted as a string
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)",
                (client_id, name, now)
            )

    def update_client_keys(self, client_id: bytes, public_key: bytes = None, aes_key: bytes = None):
        """
        Updates the public key, AES key, and LastSeen time for an existing client.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.conn:
            # If both keys are provided, update both
            if public_key and aes_key:
                self.conn.execute(
                    "UPDATE clients SET PublicKey = ?, AES = ?, LastSeen = ? WHERE ID = ?",
                    (public_key, aes_key, now, client_id)
                )
            # If only AES key is provided (like during reconnect), update only AES
            elif aes_key:
                self.conn.execute(
                    "UPDATE clients SET AES = ?, LastSeen = ? WHERE ID = ?",
                    (aes_key, now, client_id)
                )

    def record_file(self, client_id: bytes, file_name: str, path_name: str, verified: bool = False):
        """
        Saves uploaded file details into the database.
        """
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                (client_id, file_name, path_name, 1 if verified else 0)
            )

    def set_file_verified(self, client_id: bytes, file_name: str):
        """
        Marks a file as verified after the client confirms the CRC.
        """
        with self.conn:
            self.conn.execute(
                "UPDATE files SET Verified = 1 WHERE ID = ? AND FileName = ?",
                (client_id, file_name)
            )