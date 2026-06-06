# collector.py — version definitiva multisensor (NYC + Frankfurt) con Groq/Llama 3.1
import threading
import requests
import json
import time
import subprocess
import sqlite3
import os
from groq import Groq
import geoip2.database
from datetime import datetime

class Color:
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    RESET  = '\033[0m'
    BOLD   = '\033[1m'

# ==========================================
# --- 1. CONFIGURACION DEL ENTORNO SOC ---
# ==========================================
TOKEN        = "<telegram-bot-token>"
CHAT_ID      = "<telegram-chat-id>"
GROQ_API_KEY = "<groq-api-key>"

LOG_PATH    = "/opt/tfg-project/honeypot/var/log/cowrie/cowrie.json"
DB_NAME     = "/opt/tfg-project/db/honeypot_events.db"
SENSOR_PORT = 2222
GEO_DB_PATH = "/home/inigo/tfg-project/brain/GeoLite2-City.mmdb"

# LISTA DE SENSORES
SENSORS = [
    {"name": "Nueva York", "ip": "<ip-publica-nyc>", "alerts": True},
    {"name": "Frankfurt",  "ip": "<ip-publica-fra>", "alerts": False}
]

groq_client   = Groq(api_key=GROQ_API_KEY)
cola_comandos = []
bloqueo_cola  = threading.Lock()
ip_spam_cache = {}

# ==========================================
# --- 2. GESTION DE PERSISTENCIA ---
# ==========================================
def init_db():
    os.makedirs(os.path.dirname(DB_NAME), exist_ok=True)
    conn = sqlite3.connect(DB_NAME)
    conn.execute('PRAGMA journal_mode=WAL;')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            sensor TEXT,
            ip TEXT,
            location TEXT,
            country_name TEXT,
            lat REAL,
            lon REAL,
            username TEXT,
            password TEXT,
            event_type TEXT,
            input TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            num_atacantes INTEGER,
            num_comandos INTEGER,
            analisis TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_to_db(sensor, ip, location, country, lat, lon, user, pwd, event_type, command_input=None):
    try:
        conn = sqlite3.connect(DB_NAME, timeout=60)
        conn.execute('PRAGMA journal_mode=WAL;')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO events (sensor, ip, location, country_name, lat, lon, username, password, event_type, input)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (sensor, ip, location, country, lat, lon, user, pwd, event_type, command_input))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error DB: {e}")

# ==========================================
# --- 3. GEO-IP Y COORDENADAS ---
# ==========================================
def get_ip_info(ip):
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return "Red Local / VPN", "Local", 0.0, 0.0
    try:
        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            response = reader.city(ip)
            country = response.country.name or "Desconocido"
            code    = response.country.iso_code
            flag    = "".join(chr(ord(c) + 127397) for c in code.upper()) if code else ""
            city    = response.city.name
            loc_str = f"{city}, {country} {flag}" if city else f"{country} {flag}"
            lat = response.location.latitude  or 0.0
            lon = response.location.longitude or 0.0
            return loc_str, country, lat, lon
    except Exception:
        return "Ubicacion no encontrada", "Desconocido", 0.0, 0.0

# ==========================================
# --- 4. MOTOR SOC CON ANALISIS FORENSE ---
# ==========================================
def procesar_lote_ia(lote):
    if not lote:
        return "Sin amenazas activas."

    lineas = [f"- Sensor {i['sensor']} | Comando: {i['cmd'][:80]}" for i in lote]
    prompt = (
        "Actua como analista forense SOC. Analiza los comandos ejecutados por atacantes:\n\n"
        f"{chr(10).join(lineas)}\n\n"
        "REGLAS ESTRICTAS:\n"
        "1. NO uses terminologia MITRE en el cuerpo del informe.\n"
        "2. Explica tecnicamente que hace cada comando.\n\n"
        "Estructura fija:\n"
        "Analisis de Comandos:\n"
        "[Sensor] | [Comando]: explicacion tecnica breve.\n"
        "(una linea por comando distinto)\n\n"
        "Objetivo Final de la Sesion:\n"
        "[1 sola frase resumiendo la intencion global del atacante]\n\n"
        "Finaliza con: FIN_REPORTE"
    )

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": "Eres un analista tecnico directo. Sigue la estructura sin inventar apartados."},
                {"role": "user",   "content": prompt}
            ],
            model="llama-3.1-8b-instant",
            temperature=0.1,
            max_tokens=800,
        )
        respuesta = chat_completion.choices[0].message.content.strip()
        return respuesta.replace("_", "\_").replace("*", "")

    except Exception as e:
        print(f"Error en IA Groq: {e}")
        return "Analisis forense no disponible temporalmente."

def trabajador_reportes():
    while True:
        time.sleep(600)   # Reporte cada 10 minutos
        with bloqueo_cola:
            if not cola_comandos:
                continue

            analisis          = procesar_lote_ia(cola_comandos)
            ips_unicas        = len({item['ip'] for item in cola_comandos})
            num_cmds          = len(cola_comandos)
            sensores_afectados = ", ".join({item['sensor'] for item in cola_comandos})

            try:
                conn = sqlite3.connect(DB_NAME, timeout=60)
                conn.execute('PRAGMA journal_mode=WAL;')
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO ai_reports (num_atacantes, num_comandos, analisis)
                    VALUES (?, ?, ?)
                ''', (ips_unicas, num_cmds, analisis))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Error guardando reporte IA en DB: {e}")

            mensaje = (
                f"*ANALISIS FORENSE DE COMANDOS*\n"
                f"Sensores atacados: {sensores_afectados}\n"
                f"Origenes unicos: {ips_unicas}\n"
                f"Lineas ejecutadas: {num_cmds}\n\n"
                f"{analisis}"
            )
            send_telegram_message(mensaje)
            cola_comandos.clear()

# ==========================================
# --- 5. NOTIFICACIONES ---
# ==========================================
def send_telegram_message(text):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"}, timeout=10)
    except Exception as e:
        print(f"Error Telegram: {e}")

# ==========================================
# --- 6. MONITORIZACION REMOTA ---
# ==========================================
def monitor_sensor(sensor_conf):
    name       = sensor_conf['name']
    ip         = sensor_conf['ip']
    use_alerts = sensor_conf['alerts']

    ssh_cmd = (
        f"ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 "
        f"root@{ip} -p {SENSOR_PORT} 'tail -F -n 0 {LOG_PATH}'"
    )

    while True:
        try:
            process = subprocess.Popen(
                ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            for line in process.stdout:
                decoded_line = line.strip()
                try:
                    event   = json.loads(decoded_line)
                    eventid = event.get("eventid")
                    src_ip  = event.get("src_ip", "Desconocida")

                    if not eventid or src_ip == "Desconocida":
                        continue

                    loc_str, country, lat, lon = get_ip_info(src_ip)

                    if eventid == "cowrie.login.failed":
                        user = event.get("username", "???")
                        pwd  = event.get("password",  "???")
                        save_to_db(name, src_ip, loc_str, country, lat, lon, user, pwd, "FAILED")
                        if use_alerts:
                            current_time = time.time()
                            last_time    = ip_spam_cache.get(src_ip, 0)
                            if current_time - last_time > 60:
                                msg = (
                                    f"*FUERZA BRUTA EN {name.upper()}*\n"
                                    f"MITRE: T1110 (Brute Force)\n"
                                    f"IP: {src_ip} ({loc_str})\n"
                                    f"User: `{user}` | Pass: `{pwd}`"
                                )
                                send_telegram_message(msg)
                                ip_spam_cache[src_ip] = current_time

                    elif eventid == "cowrie.login.success":
                        user = event.get("username", "???")
                        save_to_db(name, src_ip, loc_str, country, lat, lon, user, "N/A", "SUCCESS")
                        if use_alerts:
                            msg = (
                                f"*ACCESO EXITOSO EN {name.upper()}*\n"
                                f"MITRE: T1021 (Remote Services)\n"
                                f"IP: {src_ip} ({loc_str})\n"
                                f"User: `{user}`"
                            )
                            send_telegram_message(msg)

                    elif eventid == "cowrie.command.input":
                        cmd_in = event.get("input", "N/A")
                        save_to_db(name, src_ip, loc_str, country, lat, lon, "N/A", "N/A", "COMMAND", cmd_in)
                        with bloqueo_cola:
                            cola_comandos.append({'sensor': name, 'ip': src_ip, 'cmd': cmd_in})

                except Exception:
                    continue
        except Exception:
            print(f"Desconexion en {name}. Reconectando en 10 s...")
            time.sleep(10)

# ==========================================
# --- 7. ARRANQUE DEL SERVICIO ---
# ==========================================
if __name__ == "__main__":
    print(f"{Color.BOLD}{Color.CYAN}SOC Global en Azure operativo. Vigilancia iniciada...{Color.RESET}")
    init_db()
    threading.Thread(target=trabajador_reportes, daemon=True).start()

    for sensor in SENSORS:
        threading.Thread(target=monitor_sensor, args=(sensor,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Vigilancia SOC detenida de forma segura.{Color.RESET}")