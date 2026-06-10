import requests
import whois
from config.settings import ABUSEIPDB_KEY


def consultar_abuseipdb(ip):
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
    url = f"http://ip-api.com/json/{ip}"

    try:
        respuesta = requests.get(url, timeout=5)
        if respuesta.status_code == 200:
            datos = respuesta.json()
            if datos.get("status") == "success":
                return {
                    "pais": datos.get("country", "Desconocido"),
                    "isp": datos.get("isp", "Desconocido"),
                    "asn": datos.get("as", "Desconocido")
                }
            else:
                return None
        else:
            return None
    except requests.RequestException as e:
        print(f"[-] Error de conexión con IP-API: {e}")
        return None


def consultar_whois(ip):
    try:
        w = whois.whois(ip)
        correos = w.emails

        if not correos:
            return None

        if isinstance(correos, list):
            for correo in correos:
                if isinstance(correo, str) and 'abuse' in correo.lower():
                    return correo
            return correos[0] if isinstance(correos[0], str) else None

        return correos if isinstance(correos, str) else None
    except Exception as e:
        print(f"[-] Error en consulta WHOIS: {e}")
        return None


def analizar_ip(ip):
    print(f"[*] Recopilando inteligencia para la IP: {ip}...")

    datos_abuse = consultar_abuseipdb(ip)
    datos_geo = consultar_geoip(ip)
    correo = consultar_whois(ip)

    if datos_abuse is None and datos_geo is None and correo is None:
        return None

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
