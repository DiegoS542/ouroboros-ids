"""
core/blacklist.py
Ouroboros IDS — Módulo de lista negra
Carga IPs peligrosas (feeds remotos + blacklist.txt local) y verifica amenazas.
"""

from core.feed_updater import cargar_blacklist_completa


def cargar_blacklist():
    """
    Descarga feeds remotos activos y fusiona con blacklist.txt local.
    Retorna un conjunto de IPs peligrosas listo para usar.
    """
    return cargar_blacklist_completa()


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
