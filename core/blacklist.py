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
