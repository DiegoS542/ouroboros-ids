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

def procesar_alertas():
    try:
        # Conexión a SQLite con modo WAL para evitar bloqueos con el script de Diego
        conn = sqlite3.connect(DB_PATH)
        conn.execute('PRAGMA journal_mode=WAL;')
        cursor = conn.cursor()

        # Buscamos eventos que el sniffer detectó pero que no hemos notificado
        # Asumimos una tabla 'alertas' con esta estructura (valídalo con Diego)
        cursor.execute("SELECT id, tipo, ip_origen, mac_origen, ip_destino, detalle FROM alertas WHERE procesada = 0")
        alertas_pendientes = cursor.fetchall()

        for alerta in alertas_pendientes:
            id_alerta, tipo, ip_origen, mac_origen, ip_destino, detalle = alerta
            
            print(f"\n[*] Procesando nueva alerta ID {id_alerta}: {tipo}")

            if tipo.upper() == "WHITELIST":
                # 1. Enviar correo de advertencia
                enviar_alerta_whitelist(ip_origen, mac_origen, detalle)
                # 2. Registrar en archivo
                registrar_evento(tipo, ip_origen, ip_destino, detalle)

            elif tipo.upper() == "BLACKLIST":
                # 1. Enviar correo de emergencia inmediato
                enviar_alerta_blacklist(ip_origen, mac_origen, ip_destino)
                registrar_evento(tipo, ip_origen, ip_destino, detalle)

                # 2. Iniciar recolección de inteligencia
                reporte = analizar_ip(ip_destino)
                
                # 3. Enviar reporte con evidencias al admin
                if reporte:
                    enviar_reporte_forense(
                        ip_origen, mac_origen, ip_destino,
                        reporte["tipo_riesgo"], reporte["score_abuso"],
                        reporte["pais"], reporte["isp"], reporte["correo_abuso"]
                    )

            # Marcar la fila como procesada para no mandar correos duplicados
            cursor.execute("UPDATE alertas SET procesada = 1 WHERE id = ?", (id_alerta,))
            conn.commit()

        conn.close()

    except sqlite3.OperationalError as e:
        # Si Diego aún no crea la tabla o la BD no existe, no rompemos el ciclo
        pass
    except Exception as e:
        print(f"[-] Error inesperado en el Worker: {e}")

def iniciar_worker():
    print("[*] Worker de Ouroboros iniciado.")
    print("[*] Monitoreando la base de datos a la espera del sniffer...")
    
    while True:
        procesar_alertas()
        time.sleep(5)  # Espera 5 segundos antes de volver a consultar

if __name__ == "__main__":
    iniciar_worker()