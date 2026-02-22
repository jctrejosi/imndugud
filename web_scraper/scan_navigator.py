import os
import sys
import time
import sqlite3
import shutil
import tempfile
import subprocess
import ctypes
import winreg
from pathlib import Path

import psutil

# --- Configuración ---
PROXY_PORT = 8080
PROXY_ADDR = f"127.0.0.1:{PROXY_PORT}"
ROOT = Path(__file__).resolve().parent
CERT_SOURCE = ROOT / "certificates" / "mitmproxy-ca-cert.p12"

TMPDIR = Path(tempfile.mkdtemp(prefix="mitm_monitor_"))
RESULTS_DIR = ROOT / "db"
DB_PATH = RESULTS_DIR / "traffic.db"
WS_DB_PATH = RESULTS_DIR / "ws_traffic.db"
RESULTS_DIR.mkdir(exist_ok=True)

ADDON_PATH = TMPDIR / "mitm_addon.py"
PROFILE_DIR = (ROOT / "chrome_session").resolve()

# --- Addon de mitmproxy ---
ADDON_CODE = r'''
from mitmproxy import http
import sqlite3, os, time, uuid, json, logging

# Configuración de logs para ver qué pasa internamente
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitm_addon")

DB_PATH = os.environ.get("MITM_DB_PATH")
WS_DB_PATH = os.environ.get("MITM_WS_DB_PATH")

# Inicialización de conexiones
_conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_ws_conn = sqlite3.connect(WS_DB_PATH, check_same_thread=False, isolation_level=None)

def safe_text(data):
    if data is None: return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")[:50000]
    return str(data)[:50000]

def response(flow: http.HTTPFlow):
    try:
        cur = _conn.cursor()
        rid = str(uuid.uuid4())
        req_body = safe_text(flow.request.get_text(strict=False)) if hasattr(flow.request, "get_text") else ""
        res_body = safe_text(flow.response.get_text(strict=False)) if (flow.response and hasattr(flow.response, "get_text")) else ""
        
        cur.execute("""
            INSERT INTO requests (
                id, ts_start, ts_end, duration, method, url, host, path, status_code,
                request_headers, response_headers, request_body, response_body, protocol
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            rid, time.time(), time.time(), 0, flow.request.method, flow.request.pretty_url, 
            flow.request.host, flow.request.path, flow.response.status_code if flow.response else 0,
            json.dumps(dict(flow.request.headers)), 
            json.dumps(dict(flow.response.headers)) if flow.response else "{}",
            req_body, res_body, flow.request.scheme
        ))
    except Exception as e:
        logger.error(f"Error HTTP: {e}")

def websocket_message(flow):
    try:
        # Intentamos obtener el mensaje de la lista de mensajes del flujo
        # Si 'flow' es un WebSocketFlow o un HTTPFlow con websocket
        if hasattr(flow, "messages") and flow.messages:
            msg = flow.messages[-1]
        elif hasattr(flow, "websocket") and flow.websocket and flow.websocket.messages:
            msg = flow.websocket.messages[-1]
        else:
            return # No hay mensajes aún

        cur = _ws_conn.cursor()
        rid = str(uuid.uuid4())
        
        # Extraer contenido de forma segura
        content = safe_text(msg.content)
        from_client = 1 if msg.from_client else 0
        
        # URL del Handshake
        url = "wss://unknown"
        # En mitmproxy moderno, el handshake está en flow.handshake_flow (si es WebSocketFlow)
        # o el propio 'flow' es el handshake (si es HTTPFlow)
        if hasattr(flow, "handshake_flow") and flow.handshake_flow:
            url = flow.handshake_flow.request.pretty_url
        elif hasattr(flow, "request"):
            url = flow.request.pretty_url

        cur.execute("INSERT INTO ws_messages (id, ts, from_client, content, flow_url) VALUES (?, ?, ?, ?, ?)", 
                    (rid, time.time(), from_client, content, url))
        
    except Exception as e:
        logger.error(f"Error WS Interno: {e}")
'''

def is_admin():
    """Verifica si el script se ejecuta como administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def init_db():
    # HTTP DB
    if DB_PATH.exists():
        try:
            os.remove(DB_PATH)
            print("🗑️ Base de datos HTTP eliminada.")
        except PermissionError:
            print("⚠️ No se pudo borrar la DB HTTP.")
            sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY,
        ts_start REAL,
        ts_end REAL,
        duration REAL,
        method TEXT,
        url TEXT,
        host TEXT,
        path TEXT,
        status_code INTEGER,
        client_ip TEXT,
        client_port INTEGER,
        server_ip TEXT,
        server_port INTEGER,
        request_headers TEXT,
        response_headers TEXT,
        request_cookies TEXT,
        response_cookies TEXT,
        request_body TEXT,
        response_body TEXT,
        bytes_sent INTEGER,
        bytes_received INTEGER,
        content_type TEXT,
        protocol TEXT
    )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON requests(url)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON requests(ts_start)")

    # WS DB
    if WS_DB_PATH.exists():
        try:
            os.remove(WS_DB_PATH)
            print("🗑️ Base de datos WS eliminada.")
        except PermissionError:
            print("⚠️ No se pudo borrar la DB WS.")
            sys.exit(1)

    conn_ws = sqlite3.connect(WS_DB_PATH)
    conn_ws.execute("""
    CREATE TABLE IF NOT EXISTS ws_messages (
        id TEXT PRIMARY KEY,
        ts REAL,
        from_client INTEGER,
        content TEXT,
        flow_url TEXT
    )
    """)


    conn.commit()
    conn.close()

def install_cert():
    cert_path = CERT_SOURCE.resolve()
    if not cert_path.exists():
        print(f"❌ ERROR: No se encontró el archivo en: {cert_path}")
        return False
    ps_script = f"""
    try {{
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2;
        $cert.Import('{cert_path}', $null, 'PersistKeySet');
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine');
        $store.Open('ReadWrite');
        $store.Add($cert);
        $store.Close();
        write-output "SUCCESS"
    }} catch {{
        write-error $_.Exception.Message
        exit 1
    }}
    """
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True,
            check=True
        )
        if "SUCCESS" in result.stdout:
            print("✅ Certificado instalado con éxito.")
            return True
        else:
            print(f"❌ Error inesperado: {result.stdout}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ FALLO Crítico al instalar certificado. {e}")
        return False

def find_chrome():
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            path, _ = winreg.QueryValueEx(key, "")
            if Path(path).exists(): return path
    except: pass
    paths = [
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LocalAppData", "")) / "Google/Chrome/Application/chrome.exe",
    ]
    for p in paths:
        if p.exists(): return str(p)
    return shutil.which("chrome") or shutil.which("google-chrome")

def launch_mitm():
    env = os.environ.copy()
    env["MITM_DB_PATH"] = str(DB_PATH.absolute())
    env["MITM_WS_DB_PATH"] = str(WS_DB_PATH.absolute())
    return subprocess.Popen(
        [
            "mitmdump",
            "--mode", "regular",
            "--listen-host", "127.0.0.1",
            "--listen-port", str(PROXY_PORT),
            "-s", str(ADDON_PATH.absolute()),
            "--set", "block_global=false",
        ],
        env=env,
        stdout=None,
        stderr=None
    )

def find_chrome_process():
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            if proc.info['name'] and 'chrome' in proc.info['name'].lower():
                return proc  # ya hay un Chrome corriendo
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def main():
    RESULTS_DIR.mkdir(exist_ok=True)

    if PROFILE_DIR.exists():
        try:
            shutil.rmtree(PROFILE_DIR)
            print("🧹 Sesión anterior limpiada.")
        except:
            print("⚠️ No se pudo limpiar la sesión.")
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)

    init_db()
    ADDON_PATH.write_text(ADDON_CODE, encoding='utf-8')

    if not is_admin():
        print("❌ ERROR: DEBES EJECUTAR COMO ADMINISTRADOR")
        sys.exit(1)

    print("--- Paso 1: Certificado ---")
    if not install_cert():
        sys.exit(1)

    print("\n--- Paso 2: Proxy ---")
    mitm = launch_mitm()
    time.sleep(3)
    if mitm.poll() is not None:
        print("❌ ERROR: mitmproxy se cerró inesperadamente.")
        sys.exit(1)
    print(f"🚀 mitmproxy activo en puerto {PROXY_PORT}")

    print("\n--- Paso 3: Navegador ---")
    chrome_exe = find_chrome()

    chrome_proc = None
    existing = find_chrome_process()
    if not existing:
        chrome_proc = subprocess.Popen([
            chrome_exe,
            f"--proxy-server=http://{PROXY_ADDR}",
            f"--user-data-dir={PROFILE_DIR}",
            "--ignore-certificate-errors",
            "--no-first-run",
            "--allow-insecure-localhost",
            "--no-default-browser-check",
            "--disable-background-timer-throttling",
            "--disable-breakpad",
            "--disable-client-side-phishing-detection",
            "--disable-component-update",
            "--disable-default-apps",
        ])

    print("\n✅ TODO EN MARCHA. Capturando tráfico... (Ctrl+C para detener)")

    try:
        while True:
            if mitm.poll() is not None:
                print("\n❌ El proxy se cayó.")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nDeteniendo servicios...")
    finally:
        if mitm:
            mitm.terminate()

        if chrome_proc:
            chrome_proc.terminate()

        print(f"✨ Finalizado. Datos en: {DB_PATH} y {WS_DB_PATH}")

if __name__ == "__main__":
    main()