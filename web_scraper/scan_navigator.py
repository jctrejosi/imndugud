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

# --- Configuración ---
PROXY_PORT = 8080
PROXY_ADDR = f"127.0.0.1:{PROXY_PORT}"
ROOT = Path(__file__).resolve().parent
CERT_SOURCE = ROOT / "certificates" / "mitmproxy-ca-cert.p12"

TMPDIR = Path(tempfile.mkdtemp(prefix="mitm_monitor_"))
RESULTS_DIR = ROOT / "db"
DB_PATH = RESULTS_DIR / "traffic.db"
RESULTS_DIR.mkdir(exist_ok=True)

ADDON_PATH = TMPDIR / "mitm_addon.py"
PROFILE_DIR = (ROOT / "chrome_session").resolve()

# --- Addon de mitmproxy ---
ADDON_CODE = r'''
from mitmproxy import http, websocket
import sqlite3, os, time, uuid, json

DB_PATH = os.environ.get("MITM_DB_PATH", "traffic.db")

# Conexión global, PRAGMA configurado solo una vez
_conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_cur = _conn.cursor()
_cur.execute("PRAGMA journal_mode=WAL")
_cur.execute("PRAGMA synchronous=NORMAL")

MAX_BODY = 100000  # truncado seguro

def safe_text(data):
    if not data:
        return ""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8", errors="replace")
        except:
            return "[BINARY]"
    if len(data) > MAX_BODY:
        return data[:MAX_BODY] + "...<TRUNCATED>"
    return data

def store_request(flow, response=True):
    rid = str(uuid.uuid4())

    ts_start = flow.request.timestamp_start
    ts_end = time.time()
    duration = ts_end - ts_start

    client_ip, client_port = None, None
    try:
        client_ip, client_port = flow.client_conn.address
    except:
        pass

    server_ip, server_port = None, None
    try:
        if flow.server_conn and flow.server_conn.ip_address:
            server_ip = str(flow.server_conn.ip_address[0])
            server_port = flow.server_conn.ip_address[1]
    except:
        pass

    req_headers = dict(flow.request.headers)
    res_headers = dict(flow.response.headers) if (flow.response and response) else {}
    req_cookies = dict(flow.request.cookies)
    res_cookies = dict(flow.response.cookies) if (flow.response and response) else {}

    req_body = safe_text(flow.request.get_text(strict=False))
    res_body = safe_text(flow.response.get_text(strict=False)) if (flow.response and response) else ""

    bytes_sent = len(flow.request.raw_content or b"")
    bytes_received = len(flow.response.raw_content or b"") if (flow.response and response) else 0
    content_type = flow.response.headers.get("content-type") if (flow.response and response) else None
    protocol = flow.request.scheme

    _cur.execute("""
        INSERT INTO requests (
            id, ts_start, ts_end, duration,
            method, url, host, path, status_code,
            client_ip, client_port, server_ip, server_port,
            request_headers, response_headers,
            request_cookies, response_cookies,
            request_body, response_body,
            bytes_sent, bytes_received,
            content_type, protocol
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        rid, ts_start, ts_end, duration,
        flow.request.method,
        flow.request.pretty_url,
        flow.request.host,
        flow.request.path,
        flow.response.status_code if (flow.response and response) else None,
        client_ip, client_port, server_ip, server_port,
        json.dumps(req_headers, ensure_ascii=False),
        json.dumps(res_headers, ensure_ascii=False),
        json.dumps(req_cookies, ensure_ascii=False),
        json.dumps(res_cookies, ensure_ascii=False),
        req_body, res_body,
        bytes_sent, bytes_received,
        content_type,
        protocol
    ))

def response(flow: http.HTTPFlow):
    store_request(flow, response=True)

def error(flow: http.HTTPFlow):
    # Guarda requests que fallaron
    store_request(flow, response=False)

# ---------- WEBSOCKET ----------
def websocket_message(flow: websocket.WebSocketData):
    """
    flow tiene los mensajes WebSocket. 
    'content' contiene el payload (bytes o str)
    """
    try:
        data = flow.content
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        print("WS:", data[:200])
    except Exception as e:
        print("Error WS:", e)
'''

def is_admin():
    """Verifica si el script se ejecuta como administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def init_db():
    # Intentamos borrar la DB si existe para asegurar el nuevo esquema
    if DB_PATH.exists():
        try:
            # Cerramos cualquier conexión remanente si fuera necesario
            # y borramos el archivo
            os.remove(DB_PATH) 
            print("🗑️ Base de datos antigua eliminada. Creando nuevo esquema con 'response_body'...")
        except PermissionError:
            print("⚠️ ADVERTENCIA: No se pudo borrar la DB (está en uso).")
            print("💡 CIERRA el Dashboard y vuelve a intentar.")
            sys.exit(1) # Es mejor parar aquí que tener errores de columna

    conn = sqlite3.connect(DB_PATH)
    # Esquema definitivo
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
    conn.commit()
    conn.close()

def install_cert():
    """Instala el certificado p12 usando clases de .NET para evitar el error de unidad 'Cert:'."""
    cert_path = CERT_SOURCE.resolve()

    if not cert_path.exists():
        print(f"❌ ERROR: No se encontró el archivo en: {cert_path}")
        return False

    # Este comando de PowerShell usa .NET directamente (System.Security.Cryptography.X509Certificates)
    # Es mucho más fiable y no depende de si la unidad 'Cert:' existe o no.
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
        print("Instalando certificado en el almacén de confianza del sistema...")
        # Ejecutamos el script de PowerShell
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
        print(f"❌ FALLO Crítico al instalar certificado.")
        # Aquí capturamos el error real que lanza Windows
        error_msg = e.stderr.strip() if e.stderr else e.stdout.strip()
        print(f"Detalle del sistema: {error_msg}")
        print("💡 ASEGÚRATE de estar ejecutando como ADMINISTRADOR.")
        return False

def find_chrome():
    """Busca Chrome en el registro de Windows y rutas comunes."""
    # 1. Registro de Windows (La vía más confiable)
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            path, _ = winreg.QueryValueEx(key, "")
            if Path(path).exists(): return path
    except: pass

    # 2. Rutas estándar
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

def main():
    # 1. Preparación de carpetas y base de datos
    RESULTS_DIR.mkdir(exist_ok=True)

    # Limpiar sesión anterior (si existe) para evitar bloqueos de Chrome
    if PROFILE_DIR.exists():
        try:
            shutil.rmtree(PROFILE_DIR) # Borra la carpeta bloqueada
            print("🧹 Sesión anterior limpiada.")
        except:
            print("⚠️ No se pudo limpiar la sesión (quizás Chrome sigue abierto).")

    PROFILE_DIR.mkdir(parents=True, exist_ok=True)

    init_db()
    ADDON_PATH.write_text(ADDON_CODE, encoding='utf-8')

    # 2. Validación de Admin
    if not is_admin():
        print("❌ ERROR: DEBES EJECUTAR COMO ADMINISTRADOR")
        sys.exit(1)

    # 3. Certificado
    print("--- Paso 1: Certificado ---")
    if not install_cert():
        sys.exit(1)

    # 4. Proxy (USANDO LA FUNCIÓN launch_mitm)
    print("\n--- Paso 2: Proxy ---")
    mitm = launch_mitm() # Usamos la función que configuramos antes
    time.sleep(3) # Damos un poco más de tiempo para que arranque

    if mitm.poll() is not None:
        print("❌ ERROR: mitmproxy se cerró inesperadamente. Revisa los mensajes arriba.")
        sys.exit(1)
    print(f"🚀 mitmproxy activo en puerto {PROXY_PORT}")

    # 5. Navegador
    print("\n--- Paso 3: Navegador ---")
    chrome_exe = find_chrome()
    if not chrome_exe:
        print("❌ ERROR: Chrome no encontrado.")
        if mitm: mitm.terminate()
        sys.exit(1)

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
        "--disable-component-update", # Evita las descargas de 'optimizationguide'
        "--disable-default-apps",# Evita que procesos en segundo plano lo bloqueen
    ])

    print("\n✅ TODO EN MARCHA. Capturando tráfico... (Presiona Ctrl+C para detener)")

    try:
        while True:
            # Verificación de que el proxy siga vivo
            if mitm.poll() is not None:
                print("\n❌ El proxy se cayó. Revisa la conexión.")

            time.sleep(2)
    except KeyboardInterrupt:
        print("\nDeteniendo servicios...")
    finally:
        if 'mitm' in locals() and mitm: mitm.terminate()
        if 'chrome_proc' in locals() and chrome_proc: chrome_proc.terminate()
        print(f"✨ Finalizado. Datos en: {DB_PATH}")

if __name__ == "__main__":
    main()