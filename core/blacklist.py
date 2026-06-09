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


def agregar_ip(ip, comentario=""):
    """
    Agrega una IP a blacklist.txt en tiempo real.
    El admin puede llamar esto desde el dashboard sin tocar el archivo.
    Retorna False si la IP ya estaba registrada.
    """
    ip = ip.strip()
    if ip in cargar_blacklist():
        print(f"[Ouroboros] IP ya registrada en blacklist: {ip}")
        return False

    with open(BLACKLIST_PATH, "a") as f:
        if comentario:
            f.write(f"\n# {comentario}\n")
        f.write(f"{ip}\n")

    print(f"[Ouroboros] IP agregada a blacklist: {ip}")
    return True


def quitar_ip(ip):
    """
    Elimina una IP de blacklist.txt (conserva comentarios y demás líneas).
    Retorna True si la IP existía y fue eliminada.
    """
    ip = ip.strip()
    with open(BLACKLIST_PATH, "r") as f:
        lineas = f.readlines()

    nuevas = [l for l in lineas if l.strip() != ip]
    if len(nuevas) == len(lineas):
        return False  # No estaba

    with open(BLACKLIST_PATH, "w") as f:
        f.writelines(nuevas)

    print(f"[Ouroboros] IP eliminada de blacklist: {ip}")
    return True
