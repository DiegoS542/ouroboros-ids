"""
services/abuse_api.py
Ouroboros IDS — Módulo de Threat Intelligence y Forense
Responsable: Jaime

Este módulo consulta APIs externas para obtener información
sobre IPs peligrosas detectadas por el sniffer.

APIs utilizadas:
    - AbuseIPDB (https://www.abuseipdb.com) → score de amenaza y tipo de riesgo
    - ip-api.com (https://ip-api.com)       → geolocalización e ISP (gratis, sin key)
    - python-whois                           → correo de abuso del proveedor
"""

import requests
import whois
from config.settings import ABUSEIPDB_KEY


def consultar_abuseipdb(ip):
    """
    Consulta AbuseIPDB para obtener el historial de reportes de una IP.
    Retorna None si la consulta falla.
    """
    if not ABUSEIPDB_KEY:
        print("[-] Advertencia: ABUSEIPDB_KEY no configurada.")
        return None

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_KEY
    }

    try:
        respuesta = requests.get(url, headers=headers, params=params, timeout=5)
        if respuesta.status_code == 200:
            datos = respuesta.json()['data']
            return {
                "score": datos.get('abuseConfidenceScore', 0),
                "tipo_riesgo": datos.get('usageType', 'Desconocido'),
                "total_reportes": datos.get('totalReports', 0),
                "ultimo_reporte": datos.get('lastReportedAt', 'N/A')
            }
        else:
            print(f"[-] Error HTTP en AbuseIPDB: {respuesta.status_code}")
            return None
    except requests.RequestException as e:
        print(f"[-] Error de conexión con AbuseIPDB: {e}")
        return None


def consultar_geoip(ip):
    """
    Consulta ip-api.com para obtener geolocalización e ISP de una IP.
    Retorna None si la consulta falla.
    """
    url = f"http://ip-api.com/json/{ip}"

    try:
        respuesta = requests.get(url, timeout=5)
        if respuesta.status_code == 200:
            datos = respuesta.json()
            if datos.get("status") == "success":
                return {
                    "pais": datos.get("country", "Desconocido"),
                    "isp": datos.get("isp", "Desconocido"),
                    "asn": datos.get("as", "Desconocido") # En la API viene como 'as'
                }
            else:
                return None
        else:
            return None
    except requests.RequestException as e:
        print(f"[-] Error de conexión con IP-API: {e}")
        return None


def consultar_whois(ip):
    """
    Consulta WHOIS para obtener el correo de abuso del proveedor.
    Retorna None si no se encuentra o la consulta falla.
    """
    try:
        w = whois.whois(ip)
        correos = w.emails
        
        if not correos:
            return None
            
        # Si devuelve una lista, buscamos el que diga 'abuse'
        if isinstance(correos, list):
            for correo in correos:
                if isinstance(correo, str) and 'abuse' in correo.lower():
                    return correo
            # Si ninguno dice abuse explícitamente, retornamos el primero
            return correos[0] if isinstance(correos[0], str) else None
            
        return correos if isinstance(correos, str) else None
    except Exception as e:
        print(f"[-] Error en consulta WHOIS: {e}")
        return None


def analizar_ip(ip):
    """
    Función principal del módulo forense.
    Combina las tres consultas anteriores en un solo reporte.
    Retorna None si todas las consultas fallan.
    """
    print(f"[*] Recopilando inteligencia para la IP: {ip}...")
    
    # Realizar las tres llamadas
    datos_abuse = consultar_abuseipdb(ip)
    datos_geo = consultar_geoip(ip)
    correo = consultar_whois(ip)

    # Si todas fallan, respetamos la regla de retornar None
    if datos_abuse is None and datos_geo is None and correo is None:
        return None

    # Normalizamos los diccionarios por si alguno falló (retornó None)
    # para no tener errores de 'NoneType object has no attribute get'
    if datos_abuse is None:
        datos_abuse = {"score": 0, "tipo_riesgo": "Desconocido", "total_reportes": 0}
    if datos_geo is None:
        datos_geo = {"pais": "Desconocido", "isp": "Desconocido", "asn": "Desconocido"}
    if correo is None:
        correo = "No disponible"

    return {
        "ip": ip,
        "score_abuso": datos_abuse.get("score", 0),
        "tipo_riesgo": datos_abuse.get("tipo_riesgo", "Desconocido"),
        "total_reportes": datos_abuse.get("total_reportes", 0),
        "pais": datos_geo.get("pais", "Desconocido"),
        "isp": datos_geo.get("isp", "Desconocido"),
        "asn": datos_geo.get("asn", "Desconocido"),
        "correo_abuso": correo
    }

