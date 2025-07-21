import logging
import sqlite3
from pydantic import BaseModel

class Database:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = None
        try:
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.create_tables()
            logging.info(f"Successfully connected to database: {self.db_file}")
        except sqlite3.Error as e:
            logging.error(f"Database connection failed: {e}")
            raise

    def create_tables(self):
        cursor = self.conn.cursor()
        # Scraped Pages Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scraped_pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, title TEXT,
            text_content TEXT, status_code INTEGER, language TEXT, structured_data TEXT,
            technologies TEXT, emails TEXT, social_links TEXT, image_metadata TEXT,
            interesting_files TEXT, js_analysis TEXT,
            scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        # Domain OSINT Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS domain_osint (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE,
            dns_records TEXT, shodan_info TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        self._add_column_if_not_exists(cursor, 'scraped_pages', 'js_analysis', 'TEXT')
        self.conn.commit()

    def _add_column_if_not_exists(self, cursor, table, column, type):
        cursor.execute(f"PRAGMA table_info({table})")
        if column not in [info[1] for info in cursor.fetchall()]:
            logging.info(f"Adding column '{column}' to {table} table.")
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {type}")

    def insert_item(self, item: BaseModel):
        sql = """
        INSERT INTO scraped_pages (
            url, title, text_content, status_code, language, structured_data,
            technologies, emails, social_links, image_metadata, interesting_files, js_analysis
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                str(item.url), item.title, item.text_content, item.status_code,
                item.language, item.structured_data, item.technologies,
                item.emails, item.social_links, item.image_metadata, 
                item.interesting_files, item.js_analysis
            ))
            self.conn.commit()
        except sqlite3.IntegrityError:
            logging.warning(f"URL already exists in DB, skipping: {item.url}")
        except sqlite3.Error as e:
            logging.error(f"Failed to insert item for URL {item.url}: {e}")

    def insert_osint_data(self, data: BaseModel):
        sql = """
        INSERT INTO domain_osint (domain, dns_records, shodan_info)
        VALUES (?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            dns_records=excluded.dns_records,
            shodan_info=excluded.shodan_info,
            last_updated=CURRENT_TIMESTAMP;
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, (data.domain, data.dns_records, data.shodan_info))
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Failed to insert OSINT data for domain {data.domain}: {e}")

    def close(self):
        if self.conn: self.conn.close()
