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

# --- Addon de mitmproxy (Misma lógica) ---
ADDON_CODE = r'''
from mitmproxy import http, websocket
import sqlite3, os, time, uuid, json

DB_PATH = os.environ.get("MITM_DB_PATH", "traffic.db")
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_cur = _conn.cursor()

def response(flow: http.HTTPFlow):
    rid = str(uuid.uuid4())
    
    # Intentar extraer el contenido de la respuesta
    content = ""
    if flow.response and flow.response.content:
        try:
            # Si es JSON, lo decodificamos y re-formateamos para que sea legible
            if "application/json" in flow.response.headers.get("content-type", "").lower():
                data = json.loads(flow.response.get_text())
                content = json.dumps(data, indent=2)
            else:
                content = flow.response.get_text()
        except:
            content = "[Contenido Binario o No Decodificable]"

    _cur.execute("INSERT INTO requests (id, ts_start, ts_end, method, url, status_code, response_body) VALUES (?,?,?,?,?,?,?)", 
                 (rid, flow.request.timestamp_start, time.time(), 
                  flow.request.method, flow.request.pretty_url, 
                  flow.response.status_code if flow.response else None,
                  content))
    _conn.commit()

def websocket_message(flow: http.HTTPFlow):
    last_msg = flow.websocket.messages[-1]
    direction = "CLIENT_TO_SERVER" if last_msg.from_client else "SERVER_TO_CLIENT"
    try:
        content = last_msg.content.decode('utf-8')
    except:
        content = last_msg.content.hex()

    is_binary = 1 if last_msg.type == websocket.MessageType.BINARY else 0
    _cur.execute("INSERT INTO ws_messages VALUES (?,?,?,?,?)",
                 (str(flow.id), time.time(), direction, content, is_binary))
    _conn.commit()
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
        CREATE TABLE requests (
            id TEXT PRIMARY KEY, ts_start REAL, ts_end REAL,
            method TEXT, url TEXT, status_code INTEGER,
            response_body TEXT
        )
    """)
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
    # Forzamos ruta absoluta para el addon y la DB
    env["MITM_DB_PATH"] = str(DB_PATH.absolute())
    return subprocess.Popen(
        ["mitmdump", "-s", str(ADDON_PATH.absolute()), "--listen-port", str(PROXY_PORT)],
        env=env,
        stdout=None, # Ver logs en consola
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