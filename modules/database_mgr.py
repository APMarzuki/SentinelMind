import sqlite3
import os

class DatabaseManager:
    def __init__(self, db_path="data/threat_intel.db"):
        self.db_path = db_path
        # Ensure the data directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._initialize_db()

    def _initialize_db(self):
        """Creates the tables for our Threat Intel if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Table for Malicious IPs/Domains
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT UNIQUE,
                    type TEXT, -- 'ipv4', 'domain', etc.
                    source TEXT, -- 'OTX', 'AbuseIPDB', etc.
                    score INTEGER,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()

    def add_indicator(self, indicator, i_type, source, score):
        """Adds or updates a threat in the local brain."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO indicators (indicator, type, source, score, last_updated)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (indicator, i_type, source, score))
                conn.commit()
        except sqlite3.Error as e:
            print(f"[-] Database Insert Error: {e}")

    def get_indicator(self, indicator):
        """
        The 'Eye' uses this to look up a captured IP.
        Returns the threat details if found, else None.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                # This helps return results as a dictionary-like object
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT indicator, type, source, score FROM indicators WHERE indicator = ?",
                    (indicator,)
                )
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
        except sqlite3.Error as e:
            print(f"[-] Database Query Error: {e}")
            return None

    def get_all_indicators(self):
        """Returns every threat known to the brain (useful for reports)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM indicators")
            return [dict(row) for row in cursor.fetchall()]