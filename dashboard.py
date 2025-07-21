import json
import logging
import os
import sqlite3
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [Dashboard] %(message)s')

def get_db_path():
    # Simplified for brevity
    return 'scraped_data.db'

@app.route('/')
def index(): return render_template('index.html')

def query_db(query, params=()):
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(query, params).fetchall()]

@app.route('/api/osint')
def get_osint_data(): return jsonify(query_db("SELECT * FROM domain_osint ORDER BY last_updated DESC LIMIT 1"))

@app.route('/api/recon_results')
def get_recon_results(): return jsonify(query_db("SELECT type, finding, status_code FROM recon_results"))

@app.route('/api/url_parameters')
def get_url_parameters(): return jsonify(query_db("SELECT url, parameter FROM url_parameters GROUP BY url, parameter"))

@app.route('/api/record/<int:record_id>')
def get_record_details(record_id):
    data = query_db("SELECT * FROM scraped_pages WHERE id = ?", (record_id,))
    return jsonify(data[0] if data else {})

# Other routes (status, data) are simplified for brevity
@app.route('/api/status')
def get_status():
    try:
        with open('status.json', 'r') as f: return jsonify(json.load(f))
    except: return jsonify({"status": "Not Running"})

@app.route('/api/data')
def get_data():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    data = query_db("SELECT id, url, title, status_code FROM scraped_pages ORDER BY scraped_at DESC LIMIT ? OFFSET ?", (per_page, offset))
    total = query_db("SELECT COUNT(*) as count FROM scraped_pages")[0]['count']
    return jsonify({"data": data, "total": total, "page": page, "per_page": per_page})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
