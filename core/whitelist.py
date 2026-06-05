"""
core/whitelist.py
Ouroboros IDS — Módulo de lista blanca
Carga y valida dispositivos autorizados por IP y MAC (Capas 2 y 3 OSI).
"""

import json
from pathlib import Path

# Ruta al archivo de lista blanca
WHITELIST_PATH = Path(__file__).resolve().parent.parent / "data" / "whitelist.json"


def cargar_whitelist():
    """
    Lee whitelist.json y retorna dos conjuntos:
    uno de IPs autorizadas y uno de MACs autorizadas.
    """
    with open(WHITELIST_PATH, "r") as f:
        data = json.load(f)

    ips  = {d["ip"].strip().upper()  for d in data["dispositivos"]}
    macs = {d["mac"].strip().upper() for d in data["dispositivos"]}

    print(f"[Ouroboros] Whitelist cargada — {len(ips)} dispositivos autorizados.")
    return ips, macs


def es_autorizado(ip, mac, ips_autorizadas, macs_autorizadas):
    """
    Verifica si una IP o MAC están en la lista blanca.
    Retorna True si el dispositivo está autorizado, False si no.
    """
    ip_norm  = ip.strip().upper()
    mac_norm = mac.strip().upper()

    return ip_norm in ips_autorizadas or mac_norm in macs_autorizadas


def agregar_dispositivo(nombre, ip, mac):
    """
    Agrega un nuevo dispositivo autorizado a whitelist.json en tiempo real.
    El admin puede llamar esto desde el dashboard sin tocar el archivo.
    """
    with open(WHITELIST_PATH, "r") as f:
        data = json.load(f)

    # Verificar que no exista ya
    for d in data["dispositivos"]:
        if d["ip"] == ip or d["mac"] == mac:
            print(f"[Ouroboros] Dispositivo ya registrado: {nombre}")
            return False

    data["dispositivos"].append({
        "nombre": nombre,
        "ip":     ip,
        "mac":    mac
    })

    with open(WHITELIST_PATH, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[Ouroboros] Dispositivo agregado: {nombre} — {ip} / {mac}")
    return True
