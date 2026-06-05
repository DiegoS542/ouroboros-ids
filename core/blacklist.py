"""
core/blacklist.py
Ouroboros IDS — Módulo de lista negra
Carga IPs peligrosas y verifica si un destino representa una amenaza.
"""

from pathlib import Path

BLACKLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "blacklist.txt"


def cargar_blacklist():
    """
    Lee blacklist.txt e ignora comentarios y líneas vacías.
    Retorna un conjunto de IPs peligrosas.
    """
    ips_peligrosas = set()

    with open(BLACKLIST_PATH, "r") as f:
        for linea in f:
            linea = linea.strip()
            # Ignorar comentarios y líneas vacías
            if linea and not linea.startswith("#"):
                ips_peligrosas.add(linea)

    print(f"[Ouroboros] Blacklist cargada — {len(ips_peligrosas)} IPs peligrosas.")
    return ips_peligrosas


def es_peligrosa(ip_destino, ips_peligrosas):
    """
    Verifica si una IP destino está en la lista negra.
    Retorna True si es peligrosa, False si es segura.
    """
    return ip_destino.strip() in ips_peligrosas
