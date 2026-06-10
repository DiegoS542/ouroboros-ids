from core.feed_updater import cargar_blacklist_completa
from pathlib import Path
BLACKLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "blacklist.txt"


def cargar_blacklist():
    return cargar_blacklist_completa()


def es_peligrosa(ip_destino, ips_peligrosas):
    return ip_destino.strip() in ips_peligrosas


def agregar_ip(ip, comentario=""):
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
    ip = ip.strip()
    with open(BLACKLIST_PATH, "r") as f:
        lineas = f.readlines()

    nuevas = [l for l in lineas if l.strip() != ip]
    if len(nuevas) == len(lineas):
        return False

    with open(BLACKLIST_PATH, "w") as f:
        f.writelines(nuevas)

    print(f"[Ouroboros] IP eliminada de blacklist: {ip}")
    return True
