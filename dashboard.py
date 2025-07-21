import json
import logging
import os
import sqlite3
import time
from flask import Flask, jsonify, render_template, request, send_file
from export import Exporter

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [Dashboard] %(message)s')

app = Flask(__name__)
STATUS_FILE = 'status.json'
COMMAND_FILE = 'command.json'
EXPORT_DIR = 'exports'

def get_db_path():
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read('config.ini')
        return config.get('main', 'database_file', fallback='scraped_data.db')
    except Exception:
        return 'scraped_data.db'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/osint')
def get_osint_data():
    """Fetches the domain-level OSINT data."""
    db_path = get_db_path()
    if not os.path.exists(db_path):
        return jsonify({"error": "Database file not found."})
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Get the most recently updated OSINT data
            cursor.execute("SELECT * FROM domain_osint ORDER BY last_updated DESC LIMIT 1")
            row = cursor.fetchone()
            return jsonify(dict(row) if row else {})
    except sqlite3.Error as e:
        return jsonify({"error": "Database query failed."}), 500

@app.route('/api/record/<int:record_id>')
def get_record_details(record_id):
    db_path = get_db_path()
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT text_content, structured_data, technologies, emails, 
                       social_links, image_metadata, interesting_files, js_analysis
                FROM scraped_pages WHERE id = ?
            """, (record_id,))
            row = cursor.fetchone()
            return jsonify(dict(row) if row else {})
    except sqlite3.Error as e:
        return jsonify({"error": "Database query failed."}), 500

@app.route('/api/status')
def get_status():
    if not os.path.exists(STATUS_FILE):
        return jsonify({
            "status": "Not Running", "crawled_count": 0, "queue_size": 0,
            "elapsed_time": "00:00:00", "crawl_rate": 0, "http_status_codes": {},
            "recent_logs": ["Scraper has not started yet. Run scraper.py to begin."]
        })
    try:
        with open(STATUS_FILE, 'r') as f:
            return jsonify(json.load(f))
    except (IOError, json.JSONDecodeError) as e:
        return jsonify({"error": "Could not read status file."}), 500

@app.route('/api/data')
def get_data():
    db_path = get_db_path()
    if not os.path.exists(db_path):
        return jsonify({"error": "Database file not found.", "data": [], "total": 0})

    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    search_term = request.args.get('search', '').strip()

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            base_query = "FROM scraped_pages"
            count_query = "SELECT COUNT(*) " + base_query
            data_query = "SELECT id, url, title, status_code, language, scraped_at " + base_query
            
            params = []
            if search_term:
                where_clause = " WHERE url LIKE ? OR title LIKE ?"
                count_query += where_clause
                data_query += where_clause
                params.extend([f'%{search_term}%', f'%{search_term}%'])

            total_rows = cursor.execute(count_query, params).fetchone()[0]
            
            data_query += " ORDER BY scraped_at DESC LIMIT ? OFFSET ?"
            params.extend([per_page, offset])
            
            rows = cursor.execute(data_query, params).fetchall()
            data = [dict(row) for row in rows]
            
            return jsonify({"data": data, "total": total_rows, "page": page, "per_page": per_page})
    except sqlite3.Error as e:
        return jsonify({"error": "Database query failed."}), 500

if __name__ == '__main__':
    if os.path.exists(COMMAND_FILE): os.remove(COMMAND_FILE)
    app.run(debug=True, port=5000)
