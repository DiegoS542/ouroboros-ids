import socket
import requests
import whois
from config.settings import ABUSEIPDB_KEY

CATEGORIAS_ABUSEIPDB = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}


def consultar_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        print("[-] Advertencia: ABUSEIPDB_KEY no configurada.")
        return None

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_KEY}

    try:
        respuesta = requests.get(url, headers=headers, params=params, timeout=5)
        if respuesta.status_code == 200:
            datos = respuesta.json()['data']
            codigos = datos.get('reports', [])
            cats_raw = set()
            for r in codigos:
                cats_raw.update(r.get('categories', []))
            categorias = ", ".join(
                CATEGORIAS_ABUSEIPDB.get(c, str(c)) for c in sorted(cats_raw)
            ) or None
            return {
                "score":          datos.get('abuseConfidenceScore', 0),
                "tipo_riesgo":    datos.get('usageType', 'Desconocido'),
                "total_reportes": datos.get('totalReports', 0),
                "ultimo_reporte": datos.get('lastReportedAt'),
                "categorias":     categorias,
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
                    "isp":  datos.get("isp", "Desconocido"),
                    "asn":  datos.get("as", "Desconocido"),
                }
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


def consultar_reverse_dns(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except Exception:
        return None


def analizar_ip(ip):
    print(f"[*] Recopilando inteligencia para la IP: {ip}...")

    datos_abuse = consultar_abuseipdb(ip)
    datos_geo   = consultar_geoip(ip)
    correo      = consultar_whois(ip)
    hostname    = consultar_reverse_dns(ip)

    if datos_abuse is None and datos_geo is None and correo is None:
        return None

    if datos_abuse is None:
        datos_abuse = {"score": 0, "tipo_riesgo": "Desconocido",
                       "total_reportes": 0, "ultimo_reporte": None, "categorias": None}
    if datos_geo is None:
        datos_geo = {"pais": "Desconocido", "isp": "Desconocido", "asn": "Desconocido"}
    if correo is None:
        correo = "No disponible"

    return {
        "ip":             ip,
        "hostname":       hostname,
        "score_abuso":    datos_abuse.get("score", 0),
        "tipo_riesgo":    datos_abuse.get("tipo_riesgo", "Desconocido"),
        "total_reportes": datos_abuse.get("total_reportes", 0),
        "ultimo_reporte": datos_abuse.get("ultimo_reporte"),
        "categorias":     datos_abuse.get("categorias"),
        "pais":           datos_geo.get("pais", "Desconocido"),
        "isp":            datos_geo.get("isp", "Desconocido"),
        "asn":            datos_geo.get("asn", "Desconocido"),
        "correo_abuso":   correo,
    }
