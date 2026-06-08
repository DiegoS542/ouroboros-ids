"""
services/worker.py
Ouroboros IDS — Motor de Procesamiento y Alertas

Monitorea la base de datos SQLite en busca de nuevos eventos detectados
por el sniffer. Orquesta el envío de correos, la recolección forense
y el registro en bitácoras.
"""

import sqlite3
import time
from config.settings import DB_PATH
from services.mailer import enviar_alerta_whitelist, enviar_alerta_blacklist, enviar_reporte_forense
from services.abuse_api import analizar_ip
from services.logger import registrar_evento


def _conectar():
    """Retorna una conexión a SQLite en modo WAL para coexistir con el sniffer."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _procesar_whitelist(conn):
    """
    Lee alertas_whitelist pendientes y envía correo de advertencia por cada una.
    Tabla: alertas_whitelist (id, timestamp, ip, mac, detalle, procesada)
    """
    cursor = conn.execute(
        "SELECT id, ip, mac, detalle FROM alertas_whitelist WHERE procesada = 0"
    )
    alertas = cursor.fetchall()

    for id_alerta, ip, mac, detalle in alertas:
        print(f"\n[*] Alerta whitelist ID {id_alerta}: dispositivo no autorizado {ip} / {mac}")

        # 1. Correo de advertencia al administrador
        enviar_alerta_whitelist(ip, mac, detalle or "")

        # 2. Registro en bitácora de archivo
        registrar_evento("WHITELIST", ip, "—", detalle or "")

        # 3. Marcar como procesada
        conn.execute(
            "UPDATE alertas_whitelist SET procesada = 1 WHERE id = ?", (id_alerta,)
        )
        conn.commit()


def _procesar_blacklist(conn):
    """
    Lee alertas_blacklist pendientes, envía correo de emergencia y reporte forense.
    Tabla: alertas_blacklist (id, timestamp, ip_origen, mac_origen, ip_peligrosa,
                              tipo_riesgo, score_abuso, pais, isp, correo_abuso, procesada)
    """
    cursor = conn.execute(
        "SELECT id, ip_origen, mac_origen, ip_peligrosa FROM alertas_blacklist WHERE procesada = 0"
    )
    alertas = cursor.fetchall()

    for id_alerta, ip_origen, mac_origen, ip_peligrosa in alertas:
        print(f"\n[*] Alerta blacklist ID {id_alerta}: {ip_origen} → IP peligrosa {ip_peligrosa}")

        # 1. Correo de emergencia inmediato
        enviar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa)
        registrar_evento("BLACKLIST", ip_origen, ip_peligrosa)

        # 2. Recolección de inteligencia forense
        reporte = analizar_ip(ip_peligrosa)

        # 3. Correo con reporte detallado si hay datos
        if reporte:
            enviar_reporte_forense(
                ip_origen, mac_origen, ip_peligrosa,
                reporte["tipo_riesgo"], reporte["score_abuso"],
                reporte["pais"], reporte["isp"], reporte["correo_abuso"]
            )

        # 4. Marcar como procesada
        conn.execute(
            "UPDATE alertas_blacklist SET procesada = 1 WHERE id = ?", (id_alerta,)
        )
        conn.commit()


def procesar_alertas():
    try:
        conn = _conectar()
        _procesar_whitelist(conn)
        _procesar_blacklist(conn)
        conn.close()

    except sqlite3.OperationalError:
        # La BD aún no existe o las tablas no están creadas — esperamos al sniffer
        pass
    except Exception as e:
        print(f"[-] Error inesperado en el Worker: {e}")


def iniciar_worker():
    print("[*] Worker de Ouroboros iniciado.")
    print("[*] Monitoreando la base de datos a la espera del sniffer...")

    while True:
        procesar_alertas()
        time.sleep(5)


if __name__ == "__main__":
    iniciar_worker()
