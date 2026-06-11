import sqlite3
from datetime import datetime
from config.settings import DB_PATH


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()

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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bitacora_dns (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_origen TEXT NOT NULL,
                dominio   TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alertas_blacklist (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      TEXT NOT NULL,
                ip_origen      TEXT NOT NULL,
                mac_origen     TEXT NOT NULL,
                ip_peligrosa   TEXT NOT NULL,
                puerto_destino INTEGER,
                protocolo      TEXT,
                procesada      INTEGER DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feed_sources (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre        TEXT NOT NULL,
                url           TEXT NOT NULL UNIQUE,
                activo        INTEGER DEFAULT 1,
                ultimo_update TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analisis_forense (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                ip             TEXT NOT NULL UNIQUE,
                hostname       TEXT,
                tipo_riesgo    TEXT,
                score_abuso    INTEGER,
                total_reportes INTEGER,
                ultimo_reporte TEXT,
                categorias     TEXT,
                pais           TEXT,
                isp            TEXT,
                correo_abuso   TEXT,
                ultimo_update  TEXT NOT NULL
            )
        """)

        _migrar_db(cursor)
        conn.commit()
    print("[Ouroboros] Base de datos inicializada correctamente.")
    inicializar_feeds_default()


def _migrar_db(cursor):
    migraciones = [
        "ALTER TABLE alertas_blacklist ADD COLUMN puerto_destino INTEGER",
        "ALTER TABLE alertas_blacklist ADD COLUMN protocolo TEXT",
        "ALTER TABLE analisis_forense ADD COLUMN hostname TEXT",
        "ALTER TABLE analisis_forense ADD COLUMN total_reportes INTEGER",
        "ALTER TABLE analisis_forense ADD COLUMN ultimo_reporte TEXT",
        "ALTER TABLE analisis_forense ADD COLUMN categorias TEXT",
    ]
    for sql in migraciones:
        try:
            cursor.execute(sql)
        except Exception:
            pass


FEEDS_DEFAULT = [
    ("Feodo Tracker",     "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("Emerging Threats",  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    ("Tor Exit Nodes",    "https://check.torproject.org/torbulkexitlist"),
    ("CINS Score",        "https://cinsscore.com/list/ci-badguys.txt"),
]


def inicializar_feeds_default():
    with get_connection() as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM feed_sources")
        if cursor.fetchone()[0] > 0:
            return

        conn.executemany(
            "INSERT INTO feed_sources (nombre, url, activo) VALUES (?, ?, 1)",
            FEEDS_DEFAULT
        )
        conn.commit()
    print(f"[Ouroboros] Feeds por defecto registrados — {len(FEEDS_DEFAULT)} fuentes.")


def actualizar_ultimo_update_feed(feed_id):
    with get_connection() as conn:
        conn.execute(
            "UPDATE feed_sources SET ultimo_update = ? WHERE id = ?",
            (datetime.now().isoformat(), feed_id)
        )
        conn.commit()


def registrar_dispositivo(ip, mac):
    ahora = datetime.now().isoformat()

    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT id, ip FROM dispositivos_conocidos WHERE mac = ?", (mac,)
        )
        existente = cursor.fetchone()

        if existente:
            conn.execute(
                "UPDATE dispositivos_conocidos SET ip = ?, ultimo_visto = ? WHERE mac = ?",
                (ip, ahora, mac)
            )
            conn.commit()
            return False
        else:
            conn.execute(
                """INSERT INTO dispositivos_conocidos
                   (ip, mac, primera_vez_visto, ultimo_visto, autorizado)
                   VALUES (?, ?, ?, ?, 0)""",
                (ip, mac, ahora, ahora)
            )
            conn.commit()
            return True


def es_autorizado(ip, mac):
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT autorizado FROM dispositivos_conocidos WHERE mac = ?", (mac,)
        )
        row = cursor.fetchone()

        if row is None:
            return False
        return row[0] == 1


def autorizar_dispositivo(mac):
    with get_connection() as conn:
        conn.execute(
            "UPDATE dispositivos_conocidos SET autorizado = 1 WHERE mac = ?", (mac,)
        )
        conn.commit()


def registrar_alerta_whitelist(ip, mac, detalle=""):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO alertas_whitelist (timestamp, ip, mac, detalle) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), ip, mac, detalle)
        )
        conn.commit()


def registrar_dns(ip_origen, dominio):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO bitacora_dns (timestamp, ip_origen, dominio) VALUES (?,?,?)",
            (datetime.now().isoformat(), ip_origen, dominio)
        )
        conn.commit()


def registrar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa,
                               puerto_destino=None, protocolo=None):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO alertas_blacklist
            (timestamp, ip_origen, mac_origen, ip_peligrosa, puerto_destino, protocolo)
            VALUES (?,?,?,?,?,?)
        """, (datetime.now().isoformat(), ip_origen, mac_origen, ip_peligrosa,
              puerto_destino, protocolo))
        conn.commit()

def registrar_analisis_forense(ip, tipo_riesgo, score_abuso, pais, isp, correo_abuso,
                                total_reportes=None, ultimo_reporte=None,
                                hostname=None, categorias=None):
    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO analisis_forense
            (ip, hostname, tipo_riesgo, score_abuso, total_reportes, ultimo_reporte,
             categorias, pais, isp, correo_abuso, ultimo_update)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, hostname, tipo_riesgo, score_abuso, total_reportes, ultimo_reporte,
              categorias, pais, isp, correo_abuso, datetime.now().isoformat()))
        conn.commit()


def autorizar_por_ip(ip):
    with get_connection() as conn:
        conn.execute(
            "UPDATE dispositivos_conocidos SET autorizado = 1 WHERE ip = ?", (ip,)
        )
        conn.commit()


def registrar_y_autorizar(ip, mac):
    registrar_dispositivo(ip, mac)
    with get_connection() as conn:
        conn.execute(
            "UPDATE dispositivos_conocidos SET autorizado = 1 WHERE mac = ?", (mac,)
        )
        conn.commit()
