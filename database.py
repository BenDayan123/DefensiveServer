import sqlite3,datetime

DB_FILE = "defensive.db"

class Database:
    def __init__(self, db_file: str = DB_FILE):
        self.conn = sqlite3.connect(db_file)
        self._create_tables()

    def _create_tables(self):
        with self.conn:
            # Table clients: ID (16B), Name (255B), PublicKey (160B), LastSeen, AES (32B)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    ID BLOB PRIMARY KEY,
                    Name TEXT,
                    PublicKey BLOB,
                    LastSeen DATETIME,
                    AES BLOB
                )
            """)
            # Table files: ID (16B), FileName (255B), PathName (255B), Verified (BOOLEAN)
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
        """Loads all registered clients into RAM on server startup for recovery."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT ID, Name, PublicKey, AES FROM clients")
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
        now = datetime.now()
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)",
                (client_id, name, now)
            )
            
    def update_client_keys(self, client_id: bytes, public_key: bytes = None, aes_key: bytes = None):
        now = datetime.now()
        with self.conn:
            if public_key and aes_key:
                self.conn.execute(
                    "UPDATE clients SET PublicKey = ?, AES = ?, LastSeen = ? WHERE ID = ?",
                    (public_key, aes_key, now, client_id)
                )
            elif aes_key:
                self.conn.execute(
                    "UPDATE clients SET AES = ?, LastSeen = ? WHERE ID = ?",
                    (aes_key, now, client_id)
                )