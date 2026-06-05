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

        # Tabla 1 — Dispositivos desconocidos detectados en la red
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alertas_whitelist (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip        TEXT NOT NULL,
                mac       TEXT NOT NULL,
                detalle   TEXT
            )
        """)

        # Tabla 2 — Bitácora de dominios visitados por dispositivos
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bitacora_dns (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_origen TEXT NOT NULL,
                dominio   TEXT NOT NULL
            )
        """)

        # Tabla 3 — Conexiones a IPs peligrosas detectadas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alertas_blacklist (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT NOT NULL,
                ip_origen    TEXT NOT NULL,
                mac_origen   TEXT NOT NULL,
                ip_peligrosa TEXT NOT NULL,
                tipo_riesgo  TEXT,
                score_abuso  INTEGER,
                pais         TEXT,
                isp          TEXT,
                correo_abuso TEXT
            )
        """)

        conn.commit()
    print("[Ouroboros] Base de datos inicializada correctamente.")


# ── Funciones de escritura ───────────────────────────────────────────────────

def registrar_alerta_whitelist(ip, mac, detalle=""):
    """Registra un dispositivo no autorizado detectado en la red."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO alertas_whitelist (timestamp, ip, mac, detalle) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), ip, mac, detalle)
        )
        conn.commit()


def registrar_dns(ip_origen, dominio):
    """Registra un dominio visitado por un dispositivo."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO bitacora_dns (timestamp, ip_origen, dominio) VALUES (?,?,?)",
            (datetime.now().isoformat(), ip_origen, dominio)
        )
        conn.commit()


def registrar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa,
                                tipo_riesgo="", score_abuso=0,
                                pais="", isp="", correo_abuso=""):
    """Registra una conexión a una IP peligrosa con todos sus metadatos forenses."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO alertas_blacklist
            (timestamp, ip_origen, mac_origen, ip_peligrosa,
             tipo_riesgo, score_abuso, pais, isp, correo_abuso)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (datetime.now().isoformat(), ip_origen, mac_origen, ip_peligrosa,
              tipo_riesgo, score_abuso, pais, isp, correo_abuso))
        conn.commit()
