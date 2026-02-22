import json
from flask import Flask, render_template, jsonify
import sqlite3
import webbrowser
import os
from threading import Timer
from pathlib import Path

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "db" / "traffic.db"

def query_db(query, args=(), one=False):
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

@app.route('/')
def index():
    # Asegúrate de que el nombre del archivo coincida con tu .html
    return render_template('traffic_history.html')

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
    rows = query_db(sql)
    # convertir a lista simple y añadir campo 'hora'
    data = []
    for r in rows:
        row = dict(r)
        row['hora'] = row.get('ts_start') and (  # convertir UNIX -> localtime ISO-like
            __import__('datetime').datetime.fromtimestamp(row['ts_start']).strftime("%Y-%m-%d %H:%M:%S")
        ) or ''
        data.append(row)
    return jsonify({"data": data})

@app.route('/api/detail/<req_id>')
def get_detail(req_id):
    row = query_db("SELECT * FROM requests WHERE id = ?", (req_id,), one=True)
    if not row:
        return jsonify({"error": "404"}), 404
    data = dict(row)

    # parsear columnas JSON si existen
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
            # dejar como string si no es JSON
            data[col] = raw

    # añadir metadata legible
    data['hora'] = data.get('ts_start') and __import__('datetime').datetime.fromtimestamp(data['ts_start']).strftime("%Y-%m-%d %H:%M:%S") or ''
    return jsonify(data)
def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

if __name__ == '__main__':
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        Timer(1.5, open_browser).start()
    app.run(debug=True, port=5000)