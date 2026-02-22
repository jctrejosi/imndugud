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
    sql = "SELECT id, method, status_code, url, datetime(ts_start, 'unixepoch', 'localtime') as hora FROM requests ORDER BY ts_start DESC"
    rows = query_db(sql)
    return jsonify({"data": [dict(row) for row in rows]})

@app.route('/api/detail/<req_id>')
def get_detail(req_id):
    row = query_db("SELECT * FROM requests WHERE id = ?", (req_id,), one=True)
    if not row:
        return jsonify({"error": "404"}), 404
    
    data = dict(row)
    body = data.get('response_body', '')

    # Lógica para detectar cifrado o formato
    is_json = False
    is_encrypted = False

    if body:
        body_trimmed = body.strip()
        # Verificar si es JSON
        if (body_trimmed.startswith('{') and body_trimmed.endswith('}')) or \
           (body_trimmed.startswith('[') and body_trimmed.endswith(']')):
            is_json = True
        # Verificar si parece cifrado (muchos caracteres alfanuméricos sin espacios, terminando en ==, etc)
        elif len(body_trimmed) > 50 and ' ' not in body_trimmed:
            is_encrypted = True

    data['meta'] = {
        "is_json": is_json,
        "is_encrypted": is_encrypted,
        "length": len(body)
    }
    
    return jsonify(data)

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

if __name__ == '__main__':
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        Timer(1.5, open_browser).start()
    app.run(debug=True, port=5000)