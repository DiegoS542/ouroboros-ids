import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config.settings import DB_PATH
from core.db_writer import init_db

DISPOSITIVOS = [
    ("192.168.1.1",   "AA:BB:CC:00:00:01", 1),
    ("192.168.1.100", "AA:BB:CC:00:00:02", 1),
    ("192.168.1.101", "AA:BB:CC:00:00:03", 1),
    ("192.168.1.200", "AA:BB:CC:00:00:04", 0),
    ("192.168.1.201", "AA:BB:CC:00:00:05", 0),
]

ALERTAS_WHITELIST = [
    ("192.168.1.200", "AA:BB:CC:00:00:04", "Tráfico hacia 8.8.8.8",          1, 3),
    ("192.168.1.201", "AA:BB:CC:00:00:05", "Tráfico hacia 1.1.1.1",          0, 1),
    ("192.168.1.202", "AA:BB:CC:00:00:06", "Tráfico hacia 185.220.101.5",    0, 0),
]

ALERTAS_BLACKLIST = [
    {
        "ip_origen":      "192.168.1.100",
        "mac_origen":     "AA:BB:CC:00:00:02",
        "ip_peligrosa":   "185.220.101.34",
        "puerto_destino": 443,
        "protocolo":      "TCP",
        "procesada":      1,
        "delta_min":      45,
    },
    {
        "ip_origen":      "192.168.1.101",
        "mac_origen":     "AA:BB:CC:00:00:03",
        "ip_peligrosa":   "91.92.109.196",
        "puerto_destino": 4444,
        "protocolo":      "TCP",
        "procesada":      1,
        "delta_min":      30,
    },
    {
        "ip_origen":      "192.168.1.200",
        "mac_origen":     "AA:BB:CC:00:00:04",
        "ip_peligrosa":   "198.235.24.138",
        "puerto_destino": 53,
        "protocolo":      "UDP",
        "procesada":      1,
        "delta_min":      15,
    },
    {
        "ip_origen":      "192.168.1.100",
        "mac_origen":     "AA:BB:CC:00:00:02",
        "ip_peligrosa":   "45.142.212.100",
        "puerto_destino": 22,
        "protocolo":      "TCP",
        "procesada":      0,
        "delta_min":      5,
    },
    {
        "ip_origen":      "192.168.1.201",
        "mac_origen":     "AA:BB:CC:00:00:05",
        "ip_peligrosa":   "77.83.36.19",
        "puerto_destino": None,
        "protocolo":      "1",
        "procesada":      0,
        "delta_min":      2,
    },
]

ANALISIS_FORENSE = [
    {
        "ip":             "185.220.101.34",
        "hostname":       "tor-exit-01.example.net",
        "tipo_riesgo":    "Tor Exit Node",
        "score_abuso":    98,
        "total_reportes": 2341,
        "ultimo_reporte": "2026-06-09T18:43:00+00:00",
        "categorias":     "Hacking, SSH, Brute-Force, Port Scan",
        "pais":           "Germany",
        "isp":            "Hetzner Online GmbH",
        "correo_abuso":   "abuse@hetzner.com",
    },
    {
        "ip":             "91.92.109.196",
        "hostname":       None,
        "tipo_riesgo":    "Data Center/Web Hosting/Transit",
        "score_abuso":    87,
        "total_reportes": 514,
        "ultimo_reporte": "2026-06-08T07:12:00+00:00",
        "categorias":     "Web App Attack, SQL Injection, Bad Web Bot",
        "pais":           "Netherlands",
        "isp":            "Serverius Holding B.V.",
        "correo_abuso":   "abuse@serverius.net",
    },
    {
        "ip":             "198.235.24.138",
        "hostname":       "scanner.shadowserver.org",
        "tipo_riesgo":    "Content Delivery Network",
        "score_abuso":    62,
        "total_reportes": 88,
        "ultimo_reporte": "2026-06-07T21:00:00+00:00",
        "categorias":     "Port Scan, DDoS Attack",
        "pais":           "United States",
        "isp":            "Cogent Communications",
        "correo_abuso":   "abuse@cogentco.com",
    },
    {
        "ip":             "45.142.212.100",
        "hostname":       "c2.malware-lab.ru",
        "tipo_riesgo":    "Fixed Line ISP",
        "score_abuso":    100,
        "total_reportes": 4102,
        "ultimo_reporte": "2026-06-10T01:33:00+00:00",
        "categorias":     "Brute-Force, SSH, Hacking, Exploited Host, IoT Targeted",
        "pais":           "Russia",
        "isp":            "Selectel",
        "correo_abuso":   "abuse@selectel.ru",
    },
]

DNS_RECORDS = [
    ("192.168.1.100", "malware-updates.io"),
    ("192.168.1.100", "c2.badactor.net"),
    ("192.168.1.101", "pastebin.com"),
    ("192.168.1.101", "api.telegram.org"),
    ("192.168.1.200", "torproject.org"),
    ("192.168.1.200", "protonmail.com"),
    ("192.168.1.100", "google.com"),
    ("192.168.1.101", "github.com"),
]


def ts(delta_min=0):
    return (datetime.now() - timedelta(minutes=delta_min)).isoformat()


def seed():
    print("[seed_demo] Inicializando base de datos...")
    init_db()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")

        print("[seed_demo] Insertando dispositivos...")
        for ip, mac, autorizado in DISPOSITIVOS:
            now = ts()
            conn.execute("""
                INSERT OR IGNORE INTO dispositivos_conocidos
                (ip, mac, primera_vez_visto, ultimo_visto, autorizado)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, mac, ts(120), now, autorizado))
            conn.execute("""
                UPDATE dispositivos_conocidos
                SET ip=?, ultimo_visto=?, autorizado=?
                WHERE mac=?
            """, (ip, now, autorizado, mac))

        print("[seed_demo] Insertando alertas whitelist...")
        for ip, mac, detalle, procesada, delta in ALERTAS_WHITELIST:
            conn.execute("""
                INSERT INTO alertas_whitelist (timestamp, ip, mac, detalle, procesada)
                VALUES (?, ?, ?, ?, ?)
            """, (ts(delta), ip, mac, detalle, procesada))

        print("[seed_demo] Insertando alertas blacklist...")
        for a in ALERTAS_BLACKLIST:
            conn.execute("""
                INSERT INTO alertas_blacklist
                (timestamp, ip_origen, mac_origen, ip_peligrosa,
                 puerto_destino, protocolo, procesada)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ts(a["delta_min"]), a["ip_origen"], a["mac_origen"],
                  a["ip_peligrosa"], a["puerto_destino"], a["protocolo"],
                  a["procesada"]))

        print("[seed_demo] Insertando análisis forense...")
        for f in ANALISIS_FORENSE:
            conn.execute("""
                INSERT OR REPLACE INTO analisis_forense
                (ip, hostname, tipo_riesgo, score_abuso, total_reportes,
                 ultimo_reporte, categorias, pais, isp, correo_abuso, ultimo_update)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (f["ip"], f["hostname"], f["tipo_riesgo"], f["score_abuso"],
                  f["total_reportes"], f["ultimo_reporte"], f["categorias"],
                  f["pais"], f["isp"], f["correo_abuso"], ts()))

        print("[seed_demo] Insertando bitácora DNS...")
        for i, (ip, dominio) in enumerate(DNS_RECORDS):
            conn.execute("""
                INSERT INTO bitacora_dns (timestamp, ip_origen, dominio)
                VALUES (?, ?, ?)
            """, (ts(i * 3), ip, dominio))

        conn.commit()

    print()
    print("[seed_demo] Listo. Resumen:")
    print(f"  Dispositivos   : {len(DISPOSITIVOS)}")
    print(f"  Alertas WL     : {len(ALERTAS_WHITELIST)}")
    print(f"  Alertas BL     : {len(ALERTAS_BLACKLIST)}")
    print(f"  Análisis forense: {len(ANALISIS_FORENSE)}")
    print(f"  Registros DNS  : {len(DNS_RECORDS)}")
    print()
    print("[seed_demo] Abre el dashboard y revisa:")
    print("  /resumen      - contadores generales")
    print("  /alertas      - dispositivos no autorizados")
    print("  /blacklist    - conexiones peligrosas con forense completo")
    print("  /dns          - dominios visitados")
    print("  /dispositivos - whitelist")


if __name__ == "__main__":
    seed()
