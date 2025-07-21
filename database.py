import logging
import sqlite3
from pydantic import BaseModel

class Database:
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scraped_pages (
            id INTEGER PRIMARY KEY, url TEXT UNIQUE, title TEXT, text_content TEXT, status_code INTEGER,
            language TEXT, structured_data TEXT, technologies TEXT, emails TEXT, social_links TEXT,
            image_metadata TEXT, interesting_files TEXT, js_analysis TEXT, cloud_buckets TEXT,
            scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS domain_osint (
            id INTEGER PRIMARY KEY, domain TEXT UNIQUE, dns_records TEXT, shodan_info TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS recon_results (
            id INTEGER PRIMARY KEY, type TEXT, finding TEXT UNIQUE, status_code INTEGER
        );""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_parameters (
            id INTEGER PRIMARY KEY, url TEXT, parameter TEXT, UNIQUE(url, parameter)
        );""")
        self._add_column_if_not_exists(cursor, 'scraped_pages', 'cloud_buckets', 'TEXT')
        self.conn.commit()

    def _add_column_if_not_exists(self, cursor, table, column, type):
        cursor.execute(f"PRAGMA table_info({table})")
        if column not in [info[1] for info in cursor.fetchall()]:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {type}")

    def insert_item(self, item: BaseModel):
        sql = """INSERT OR IGNORE INTO scraped_pages (url, title, text_content, status_code, language,
            structured_data, technologies, emails, social_links, image_metadata, interesting_files,
            js_analysis, cloud_buckets) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);"""
        self.conn.execute(sql, (str(item.url), item.title, item.text_content, item.status_code,
            item.language, item.structured_data, item.technologies, item.emails, item.social_links,
            item.image_metadata, item.interesting_files, item.js_analysis, item.cloud_buckets))
        self.conn.commit()

    def insert_osint_data(self, data: BaseModel):
        sql = """INSERT INTO domain_osint (domain, dns_records, shodan_info) VALUES (?,?,?)
                 ON CONFLICT(domain) DO UPDATE SET dns_records=excluded.dns_records, shodan_info=excluded.shodan_info;"""
        self.conn.execute(sql, (data.domain, data.dns_records, data.shodan_info))
        self.conn.commit()

    def insert_recon_result(self, data: BaseModel):
        sql = "INSERT OR IGNORE INTO recon_results (type, finding, status_code) VALUES (?,?,?);"
        self.conn.execute(sql, (data.type, data.finding, data.status_code))
        self.conn.commit()

    def insert_url_parameter(self, data: BaseModel):
        sql = "INSERT OR IGNORE INTO url_parameters (url, parameter) VALUES (?,?);"
        self.conn.execute(sql, (data.url, data.parameter))
        self.conn.commit()

    def close(self): self.conn.close()
