import sqlite3

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