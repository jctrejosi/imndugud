import json
from flask import Flask, render_template, jsonify
import sqlite3
import webbrowser
import os
from threading import Timer
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent
HTTP_DB_PATH = ROOT / "db" / "traffic.db"
WS_DB_PATH = ROOT / "db" / "ws_traffic.db"

# --- helpers ---
def query_db(db_path, query, args=(), one=False):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def format_time(ts):
    if not ts:
        return ""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

# --- rutas ---
@app.route('/')
def index():
    return render_template('traffic_history.html')  # HTML puede manejar HTTP + WS tabs

# HTTP tráfico
@app.route('/api/traffic')
def get_traffic():
    sql = """
        SELECT id, method, status_code, url, host, path,
                request_body, response_body,
                ts_start, duration, bytes_sent, bytes_received,
                content_type, protocol
        FROM requests
        ORDER BY ts_start DESC
        LIMIT 1000
    """
    rows = query_db(HTTP_DB_PATH, sql)
    data = []
    for r in rows:
        row = dict(r)
        row['hora'] = format_time(row.get('ts_start'))
        data.append(row)
    return jsonify({"data": data})

# WS tráfico
@app.route('/api/ws')
def get_ws():
    sql = """
        SELECT id, ts, from_client, content, flow_url
        FROM ws_messages
        ORDER BY ts DESC
        LIMIT 1000
    """
    rows = query_db(WS_DB_PATH, sql)
    data = []
    for r in rows:
        row = dict(r)
        row['hora'] = format_time(row.get('ts'))
        data.append(row)
    return jsonify({"data": data})

# detalle HTTP
@app.route('/api/detail/<req_id>')
def get_detail(req_id):
    row = query_db(HTTP_DB_PATH, "SELECT * FROM requests WHERE id = ?", (req_id,), one=True)
    if not row:
        return jsonify({"error": "404"}), 404
    data = dict(row)

    for col in ('request_headers','response_headers','request_cookies','response_cookies'):
        raw = data.get(col)
        if raw is None:
            data[col] = {}
            continue
        if isinstance(raw, (dict,list)):
            continue
        try:
            data[col] = json.loads(raw)
        except Exception:
            data[col] = raw

    data['hora'] = format_time(data.get('ts_start'))
    return jsonify(data)

# detalle WS
@app.route('/api/ws_detail/<msg_id>')
def get_ws_detail(msg_id):
    row = query_db(WS_DB_PATH, "SELECT * FROM ws_messages WHERE id = ?", (msg_id,), one=True)
    if not row:
        return jsonify({"error": "404"}), 404
    data = dict(row)
    data['hora'] = format_time(data.get('ts'))
    return jsonify(data)

# abrir navegador
def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

if __name__ == '__main__':
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        Timer(1.5, open_browser).start()
    app.run(debug=True, port=5000)