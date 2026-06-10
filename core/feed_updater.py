import ipaddress
import sqlite3
from datetime import datetime
from pathlib import Path

import requests

from config.settings import DB_PATH

BLACKLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "blacklist.txt"


def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _parsear_feed(texto):
    ips = set()
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        try:
            ipaddress.ip_address(linea)
            ips.add(linea)
        except ValueError:
            pass
    return ips


def _cargar_feeds_remotos():
    ips = set()

    try:
        conn = _get_connection()
        cursor = conn.execute("SELECT id, nombre, url FROM feed_sources WHERE activo = 1")
        feeds = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"[Blacklist] Error al consultar feed_sources: {e}")
        return ips

    for feed in feeds:
        feed_id, nombre, url = feed["id"], feed["nombre"], feed["url"]
        try:
            respuesta = requests.get(url, timeout=10)
            respuesta.raise_for_status()
            nuevas = _parsear_feed(respuesta.text)
            ips.update(nuevas)

            from core.db_writer import actualizar_ultimo_update_feed
            actualizar_ultimo_update_feed(feed_id)

            print(f"[Blacklist] {nombre} — {len(nuevas)} IPs descargadas.")
        except Exception as e:
            print(f"[Blacklist] {nombre} no disponible ({e}) — continuando.")

    return ips


def _cargar_blacklist_local():
    ips = set()
    try:
        with open(BLACKLIST_PATH, "r") as f:
            for linea in f:
                linea = linea.strip()
                if not linea or linea.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(linea)
                    ips.add(linea)
                except ValueError:
                    pass
    except FileNotFoundError:
        print(f"[Blacklist] blacklist.txt no encontrada en {BLACKLIST_PATH} — omitida.")
    return ips


def cargar_blacklist_completa():
    try:
        ips_remotas = _cargar_feeds_remotos()
        ips_locales = _cargar_blacklist_local()
        total = ips_remotas | ips_locales
        print(f"[Ouroboros] Blacklist — {len(total)} IPs peligrosas "
              f"({len(ips_remotas)} remotas + {len(ips_locales)} locales).")
        return total
    except Exception as e:
        print(f"[Blacklist] Error inesperado al cargar blacklist: {e}")
        return set()
