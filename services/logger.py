"""
services/logger.py
Ouroboros IDS — Módulo de Bitácoras
Responsable: Jaime
"""

from datetime import datetime
from config.settings import BASE_DIR

ARCHIVO_LOG = BASE_DIR / "data" / "ids_bitacora.log"

def registrar_evento(tipo_evento, ip_origen, destino, detalle=""):
    """
    Escribe una línea en el archivo de bitácora con formato estructurado.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea_log = f"[{timestamp}] | EVENTO: {tipo_evento.upper()} | ORIGEN: {ip_origen} | DESTINO: {destino} | DETALLE: {detalle}\n"
    
    try:
        with open(ARCHIVO_LOG, "a", encoding="utf-8") as archivo:
            archivo.write(linea_log)
        return True
    except Exception as e:
        print(f"[-] Error al intentar escribir en la bitácora: {e}")
        return False