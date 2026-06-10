import sqlite3
import time
from config.settings import DB_PATH
from services.mailer import enviar_alerta_whitelist, enviar_alerta_blacklist, enviar_reporte_forense
from services.abuse_api import analizar_ip
from services.logger import registrar_evento
from core.db_writer import registrar_analisis_forense


def _conectar():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _procesar_whitelist(conn):
    cursor = conn.execute(
        "SELECT id, ip, mac, detalle FROM alertas_whitelist WHERE procesada = 0"
    )
    alertas = cursor.fetchall()

    for id_alerta, ip, mac, detalle in alertas:
        enviar_alerta_whitelist(ip, mac, detalle or "")

        registrar_evento("WHITELIST", ip, "—", detalle or "")

        conn.execute(
            "UPDATE alertas_whitelist SET procesada = 1 WHERE id = ?", (id_alerta,)
        )
        conn.commit()


def _procesar_blacklist(conn):
    cursor = conn.execute(
        "SELECT id, ip_origen, mac_origen, ip_peligrosa FROM alertas_blacklist WHERE procesada = 0"
    )
    alertas = cursor.fetchall()

    for id_alerta, ip_origen, mac_origen, ip_peligrosa in alertas:
        enviar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa)
        registrar_evento("BLACKLIST", ip_origen, ip_peligrosa)

        reporte = analizar_ip(ip_peligrosa)

        if reporte:
            registrar_analisis_forense(
                ip_peligrosa,
                reporte["tipo_riesgo"], reporte["score_abuso"],
                reporte["pais"], reporte["isp"], reporte["correo_abuso"]
            )

            enviar_reporte_forense(
                ip_origen, mac_origen, ip_peligrosa,
                reporte["tipo_riesgo"], reporte["score_abuso"],
                reporte["pais"], reporte["isp"], reporte["correo_abuso"]
            )

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
        pass
    except Exception:
        pass


def iniciar_worker():
    while True:
        procesar_alertas()
        time.sleep(5)


if __name__ == "__main__":
    iniciar_worker()
