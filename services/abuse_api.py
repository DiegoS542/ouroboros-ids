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

Funciones requeridas:
    - consultar_abuseipdb() → score, tipo de riesgo, total reportes
    - consultar_geoip()     → país, ISP, ASN
    - consultar_whois()     → correo de abuso del proveedor
    - analizar_ip()         → función principal que combina las tres anteriores
"""

import requests
import whois
from config.settings import ABUSEIPDB_KEY


def consultar_abuseipdb(ip):
    """
    Consulta AbuseIPDB para obtener el historial de reportes de una IP.

    Parámetros:
        ip — IP a consultar (str)

    Endpoint:
        GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}
        Headers: Key: ABUSEIPDB_KEY, Accept: application/json

    Retorna diccionario con:
        {
            "score":          int,   # 0-100, qué tan peligrosa es
            "tipo_riesgo":    str,   # ej: "Tor Exit Node", "Botnet"
            "total_reportes": int,   # cuántas veces ha sido reportada
            "ultimo_reporte": str    # fecha del último reporte
        }

    Retorna None si la consulta falla.
    """
    pass


def consultar_geoip(ip):
    """
    Consulta ip-api.com para obtener geolocalización e ISP de una IP.
    Esta API es gratuita y no requiere key.
    Parámetros:
        ip — IP a consultar (str)

    Endpoint:
        GET http://ip-api.com/json/{ip}

    Retorna diccionario con:
        {
            "pais": str,  # ej: "United States"
            "isp":  str,  # ej: "Emerald Onion"
            "asn":  str   # ej: "AS396507"
        }

    Retorna None si la consulta falla.
    """
    pass


def consultar_whois(ip):
    """
    Consulta WHOIS para obtener el correo de abuso del proveedor.

    Parámetros:
        ip — IP a consultar (str)

    Uso:
        import whois
        w = whois.whois(ip)
        # w.emails contiene lista de correos de contacto

    Retorna:
        str — correo de abuso, ej: "abuse@emeraldonion.org"
        None si no se encuentra o la consulta falla.
    """
    pass


def analizar_ip(ip):
    """
    Función principal del módulo forense.
    Combina las tres consultas anteriores en un solo reporte.
    Esta es la función que llama el sniffer cuando detecta una IP peligrosa.

    Parámetros:
        ip — IP peligrosa a analizar (str)

    Retorna diccionario completo con:
        {
            "ip":            str,
            "score_abuso":   int,
            "tipo_riesgo":   str,
            "total_reportes": int,
            "pais":          str,
            "isp":           str,
            "asn":           str,
            "correo_abuso":  str
        }

    Retorna None si todas las consultas fallan.
    """
    pass
