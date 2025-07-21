import logging
import sqlite3
from pydantic import BaseModel

class Database:
    """Handles all interactions with the SQLite database."""

    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = None
        try:
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.create_table()
            logging.info(f"Successfully connected to database: {self.db_file}")
        except sqlite3.Error as e:
            logging.error(f"Database connection failed: {e}")
            raise

    def create_table(self):
        """Creates/updates the 'scraped_pages' table with all required columns."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS scraped_pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            title TEXT,
            text_content TEXT,
            status_code INTEGER,
            language TEXT,
            structured_data TEXT,
            scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(create_table_sql)
            # Add new columns if they don't exist for backward compatibility
            self._add_column_if_not_exists(cursor, 'language', 'TEXT')
            self._add_column_if_not_exists(cursor, 'structured_data', 'TEXT')
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Table creation/update failed: {e}")

    def _add_column_if_not_exists(self, cursor, column_name, column_type):
        """Utility to add a column to the table if it doesn't already exist."""
        cursor.execute(f"PRAGMA table_info(scraped_pages)")
        columns = [info[1] for info in cursor.fetchall()]
        if column_name not in columns:
            logging.info(f"Adding column '{column_name}' to scraped_pages table.")
            cursor.execute(f"ALTER TABLE scraped_pages ADD COLUMN {column_name} {column_type}")

    def insert_item(self, item: BaseModel):
        """Inserts a validated ScrapedItem into the database."""
        insert_sql = """
        INSERT INTO scraped_pages (url, title, text_content, status_code, language, structured_data)
        VALUES (?, ?, ?, ?, ?, ?);
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(insert_sql, (
                str(item.url), item.title, item.text_content, item.status_code,
                item.language, item.structured_data
            ))
            self.conn.commit()
        except sqlite3.IntegrityError:
            logging.warning(f"URL already exists in DB, skipping: {item.url}")
        except sqlite3.Error as e:
            logging.error(f"Failed to insert item for URL {item.url}: {e}")

    def close(self):
        if self.conn:
            self.conn.close()
            logging.info("Database connection closed.")
