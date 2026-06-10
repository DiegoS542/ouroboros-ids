"""
core/db_writer.py
Ouroboros IDS — Módulo de base de datos
Inicializa SQLite y expone funciones de escritura para todos los módulos.
"""

import sqlite3
from datetime import datetime
from config.settings import DB_PATH


def get_connection():
    """Retorna una conexión a la base de datos SQLite."""
    return sqlite3.connect(DB_PATH)


def init_db():
    """
    Crea las tablas si no existen.
    Se llama una sola vez al arrancar Ouroboros.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # Tabla 1 — Dispositivos detectados en la red (whitelist dinámica)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dispositivos_conocidos (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                ip                TEXT NOT NULL,
                mac               TEXT NOT NULL,
                primera_vez_visto TEXT NOT NULL,
                ultimo_visto      TEXT NOT NULL,
                autorizado        INTEGER DEFAULT 0,
                UNIQUE(mac)
            )
        """)

        # Tabla 2 — Alertas de dispositivos no autorizados
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alertas_whitelist (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip        TEXT NOT NULL,
                mac       TEXT NOT NULL,
                detalle   TEXT,
                procesada INTEGER DEFAULT 0
            )
        """)

        # Tabla 3 — Bitácora de dominios visitados
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bitacora_dns (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_origen TEXT NOT NULL,
                dominio   TEXT NOT NULL
            )
        """)

        # Tabla 4 — Conexiones a IPs peligrosas
        # Los datos forenses (tipo_riesgo, score, etc.) viven en analisis_forense
        # para evitar duplicar inteligencia cuando la misma IP dispara N alertas.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alertas_blacklist (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT NOT NULL,
                ip_origen    TEXT NOT NULL,
                mac_origen   TEXT NOT NULL,
                ip_peligrosa TEXT NOT NULL,
                procesada    INTEGER DEFAULT 0
            )
        """)

        # Tabla 5 — Fuentes de feeds de IPs peligrosas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feed_sources (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre        TEXT NOT NULL,
                url           TEXT NOT NULL UNIQUE,
                activo        INTEGER DEFAULT 1,
                ultimo_update TEXT
            )
        """)

        # Tabla 6 — Análisis forense por IP (una fila por IP única)
        # Desacoplado de alertas_blacklist para evitar duplicar inteligencia
        # cuando la misma IP peligrosa dispara múltiples alertas.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analisis_forense (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ip            TEXT NOT NULL UNIQUE,
                tipo_riesgo   TEXT,
                score_abuso   INTEGER,
                pais          TEXT,
                isp           TEXT,
                correo_abuso  TEXT,
                ultimo_update TEXT NOT NULL
            )
        """)

        conn.commit()
    print("[Ouroboros] Base de datos inicializada correctamente.")
    inicializar_feeds_default()


FEEDS_DEFAULT = [
    ("Feodo Tracker",     "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("Emerging Threats",  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    ("Tor Exit Nodes",    "https://check.torproject.org/torbulkexitlist"),
    ("CINS Score",        "https://cinsscore.com/list/ci-badguys.txt"),
]


def inicializar_feeds_default():
    """
    Inserta los feeds por defecto solo si la tabla feed_sources está vacía.
    Se llama automáticamente desde init_db() en cada arranque.
    """
    with get_connection() as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM feed_sources")
        if cursor.fetchone()[0] > 0:
            return  # Ya hay feeds registrados, no tocar

        conn.executemany(
            "INSERT INTO feed_sources (nombre, url, activo) VALUES (?, ?, 1)",
            FEEDS_DEFAULT
        )
        conn.commit()
    print(f"[Ouroboros] Feeds por defecto registrados — {len(FEEDS_DEFAULT)} fuentes.")


def actualizar_ultimo_update_feed(feed_id):
    """Actualiza el timestamp de descarga exitosa de un feed."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE feed_sources SET ultimo_update = ? WHERE id = ?",
            (datetime.now().isoformat(), feed_id)
        )
        conn.commit()


# ── dispositivos_conocidos ───────────────────────────────────────────────────

def registrar_dispositivo(ip, mac):
    """
    Registra un dispositivo detectado via ARP.
    Si la MAC ya existe, actualiza la IP y el timestamp de ultimo_visto.
    Retorna True si es un dispositivo nuevo, False si ya existía.
    """
    ahora = datetime.now().isoformat()

    with get_connection() as conn:
        # Buscar si la MAC ya existe
        cursor = conn.execute(
            "SELECT id, ip FROM dispositivos_conocidos WHERE mac = ?", (mac,)
        )
        existente = cursor.fetchone()

        if existente:
            # Actualizar IP y ultimo_visto — la IP puede cambiar por DHCP
            conn.execute(
                "UPDATE dispositivos_conocidos SET ip = ?, ultimo_visto = ? WHERE mac = ?",
                (ip, ahora, mac)
            )
            conn.commit()
            return False  # No es nuevo
        else:
            # Registrar dispositivo nuevo
            conn.execute(
                """INSERT INTO dispositivos_conocidos
                   (ip, mac, primera_vez_visto, ultimo_visto, autorizado)
                   VALUES (?, ?, ?, ?, 0)""",
                (ip, mac, ahora, ahora)
            )
            conn.commit()
            return True  # Es nuevo


def es_autorizado(ip, mac):
    """
    Verifica si un dispositivo está autorizado.
    Busca por MAC — la IP puede cambiar por DHCP pero la MAC es el identificador real.
    Retorna True si está autorizado, False si no.
    """
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT autorizado FROM dispositivos_conocidos WHERE mac = ?", (mac,)
        )
        row = cursor.fetchone()

        if row is None:
            return False  # Nunca visto
        return row[0] == 1  # 1 = autorizado


def autorizar_dispositivo(mac):
    """
    Autoriza un dispositivo manualmente.
    El admin llama esto desde el dashboard cuando reconoce un dispositivo.
    """
    with get_connection() as conn:
        conn.execute(
            "UPDATE dispositivos_conocidos SET autorizado = 1 WHERE mac = ?", (mac,)
        )
        conn.commit()


# ── alertas_whitelist ────────────────────────────────────────────────────────

def registrar_alerta_whitelist(ip, mac, detalle=""):
    """Registra un dispositivo no autorizado detectado en la red."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO alertas_whitelist (timestamp, ip, mac, detalle) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), ip, mac, detalle)
        )
        conn.commit()


# ── bitacora_dns ─────────────────────────────────────────────────────────────

def registrar_dns(ip_origen, dominio):
    """Registra un dominio visitado por un dispositivo."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO bitacora_dns (timestamp, ip_origen, dominio) VALUES (?,?,?)",
            (datetime.now().isoformat(), ip_origen, dominio)
        )
        conn.commit()


# ── alertas_blacklist ────────────────────────────────────────────────────────

def registrar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa):
    """Registra una conexión a una IP peligrosa. El análisis forense
    se persiste por separado en analisis_forense (una fila por IP única)."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO alertas_blacklist
            (timestamp, ip_origen, mac_origen, ip_peligrosa)
            VALUES (?,?,?,?)
        """, (datetime.now().isoformat(), ip_origen, mac_origen, ip_peligrosa))
        conn.commit()

def registrar_analisis_forense(ip, tipo_riesgo, score_abuso, pais, isp, correo_abuso):
    """
    Persiste el análisis forense de una IP peligrosa.
    Usa INSERT OR REPLACE — si la IP ya fue analizada, actualiza los datos
    en lugar de duplicar la fila. Así 10 alertas de la misma IP producen
    un solo registro de inteligencia siempre actualizado.
    """
    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO analisis_forense
            (ip, tipo_riesgo, score_abuso, pais, isp, correo_abuso, ultimo_update)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip, tipo_riesgo, score_abuso, pais, isp, correo_abuso,
              datetime.now().isoformat()))
        conn.commit()


def autorizar_por_ip(ip):
    """
    Autoriza un dispositivo buscándolo por IP.
    Se usa al arrancar para autorizar el gateway y la propia máquina.
    """
    with get_connection() as conn:
        conn.execute(
            "UPDATE dispositivos_conocidos SET autorizado = 1 WHERE ip = ?", (ip,)
        )
        conn.commit()


def registrar_y_autorizar(ip, mac):
    """
    Registra un dispositivo y lo autoriza inmediatamente.
    Se usa para la propia máquina y el gateway al arrancar.
    """
    registrar_dispositivo(ip, mac)
    with get_connection() as conn:
        conn.execute(
            "UPDATE dispositivos_conocidos SET autorizado = 1 WHERE mac = ?", (mac,)
        )
        conn.commit()