"""
seed_demo.py
Ouroboros IDS — Generador de datos de prueba
Llena la base de datos con datos falsos para probar el dashboard
SIN necesidad de tener el sniffer corriendo.

Uso:
    python seed_demo.py          # agrega datos demo
    python seed_demo.py --reset  # vacía las tablas y las llena con datos demo
"""

import sys
import random
from datetime import datetime, timedelta

from config.settings import DB_PATH
from core import db_writer


DISPOSITIVOS = [
    ("192.168.1.65",  "AA:BB:CC:DD:EE:FF", 1),   # Laptop Diego (autorizado)
    ("192.168.1.1",   "11:22:33:44:55:66", 1),   # Router (autorizado)
    ("192.168.1.70",  "DE:AD:BE:EF:00:01", 1),   # PC Sergio (autorizado)
    ("192.168.1.102", "CA:FE:BA:BE:00:02", 0),   # Celular desconocido
    ("192.168.1.133", "BA:DC:0F:FE:E0:03", 0),   # Intruso
]

DOMINIOS = [
    "google.com", "facebook.com", "youtube.com", "uach.mx",
    "github.com", "stackoverflow.com", "netflix.com", "chatgpt.com",
    "mercadolibre.com.mx", "spotify.com", "totally-not-malware.ru",
]

IPS_PELIGROSAS = [
    ("185.220.101.45", "Botnet/C2",       95, "RU", "EvilHost LLC",   "abuse@evilhost.ru"),
    ("103.149.13.7",   "Malware/Phishing", 88, "CN", "ShadyCloud Ltd", "abuse@shadycloud.cn"),
    ("45.155.205.233", "Ransomware",      100, "NL", "BulletProof BV", "abuse@bp-hosting.nl"),
]


def ts_aleatorio(horas_atras=24):
    """Timestamp aleatorio dentro de las últimas N horas."""
    delta = timedelta(minutes=random.randint(0, horas_atras * 60))
    return (datetime.now() - delta).isoformat()


def insertar(query, params):
    """Inserta directo para poder controlar el timestamp."""
    with db_writer.get_connection() as conn:
        conn.execute(query, params)
        conn.commit()


def main():
    db_writer.init_db()

    if "--reset" in sys.argv:
        with db_writer.get_connection() as conn:
            for tabla in ("dispositivos_conocidos", "alertas_whitelist",
                          "bitacora_dns", "alertas_blacklist"):
                conn.execute(f"DELETE FROM {tabla}")
            conn.commit()
        print(f"[Demo] Tablas vaciadas en: {DB_PATH}")

    # 1. Dispositivos
    for ip, mac, autorizado in DISPOSITIVOS:
        insertar(
            """INSERT OR IGNORE INTO dispositivos_conocidos
               (ip, mac, primera_vez_visto, ultimo_visto, autorizado)
               VALUES (?,?,?,?,?)""",
            (ip, mac, ts_aleatorio(72), ts_aleatorio(1), autorizado),
        )
    print(f"[Demo] {len(DISPOSITIVOS)} dispositivos insertados.")

    # 2. Alertas de whitelist (dispositivos no autorizados)
    no_autorizados = [d for d in DISPOSITIVOS if d[2] == 0]
    for _ in range(6):
        ip, mac, _ = random.choice(no_autorizados)
        insertar(
            "INSERT INTO alertas_whitelist (timestamp, ip, mac, detalle) VALUES (?,?,?,?)",
            (ts_aleatorio(12), ip, mac, "Dispositivo no autorizado detectado vía ARP"),
        )
    print("[Demo] 6 alertas de whitelist insertadas.")

    # 3. Bitácora DNS
    for _ in range(40):
        ip = random.choice(DISPOSITIVOS)[0]
        insertar(
            "INSERT INTO bitacora_dns (timestamp, ip_origen, dominio) VALUES (?,?,?)",
            (ts_aleatorio(8), ip, random.choice(DOMINIOS)),
        )
    print("[Demo] 40 registros DNS insertados.")

    # 4. Alertas de blacklist (IPs peligrosas)
    for ip_mala, riesgo, score, pais, isp, correo in IPS_PELIGROSAS:
        ip, mac, _ = random.choice(DISPOSITIVOS)
        insertar(
            """INSERT INTO alertas_blacklist
               (timestamp, ip_origen, mac_origen, ip_peligrosa,
                tipo_riesgo, score_abuso, pais, isp, correo_abuso)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (ts_aleatorio(6), ip, mac, ip_mala, riesgo, score, pais, isp, correo),
        )
    print(f"[Demo] {len(IPS_PELIGROSAS)} alertas de blacklist insertadas.")

    print(f"\n[Demo] Listo. Base de datos en: {DB_PATH}")
    print("[Demo] Ahora corre:  python dashboard.py")


if __name__ == "__main__":
    main()
