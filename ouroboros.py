"""
ouroboros.py
Ouroboros IDS — Punto de entrada principal
Autor: Diego

Arranca el sistema completo:
    1. Valida que todas las variables de entorno estén configuradas
    2. Detecta la interfaz de red disponible
    3. Inicializa el sniffer
    4. Arranca dos hilos en paralelo:
         Hilo 1 — sniffer (captura paquetes)
         Hilo 2 — worker (monitorea SQLite y manda correos)

Uso:
    sudo venv/bin/python ouroboros.py
    sudo venv/bin/python ouroboros.py --interfaz eth0
"""

import argparse
import threading
import netifaces
from config.settings import validate
from core.sniffer import OuroborosSniffer
from services.worker import iniciar_worker


def detectar_interfaz():
    """
    Detecta automáticamente la primera interfaz de red disponible
    que no sea loopback (lo).

    Retorna el nombre de la interfaz, ej: 'wlan0', 'eth0', 'enp3s0'
    Si no encuentra ninguna, retorna 'lo' como fallback.
    """
    interfaces = netifaces.interfaces()

    for interfaz in interfaces:
        # Ignorar loopback
        if interfaz == "lo":
            continue

        # Verificar que tenga dirección IP asignada
        addrs = netifaces.ifaddresses(interfaz)
        if netifaces.AF_INET in addrs:
            return interfaz

    return "lo"


def main():
    # ── Banner ───────────────────────────────────────────────────────────────
    print("""
    ╔═══════════════════════════════════════════╗
    ║           OUROBOROS IDS v1.0              ║
    ║     Sistema de Detección de Intrusos      ║
    ║                                           ║
    ║  "El ciclo eterno de los ataques          ║
    ║        y las amenazas"                    ║
    ╚═══════════════════════════════════════════╝
    """)

    # ── Parser de argumentos ─────────────────────────────────────────────────
    # Permite especificar la interfaz manualmente si se desea
    # Ejemplo: sudo python ouroboros.py --interfaz eth0
    parser = argparse.ArgumentParser(description="Ouroboros IDS — Sistema de Detección de Intrusos")
    parser.add_argument(
        "--interfaz",
        type=str,
        default=None,
        help="Interfaz de red a monitorear (ej: wlan0, eth0). Si no se especifica, se detecta automáticamente."
    )
    args = parser.parse_args()

    # ── Validar credenciales ─────────────────────────────────────────────────
    # Si falta alguna variable en .env, el sistema para aquí con mensaje claro
    print("[Ouroboros] Validando configuración...")
    try:
        validate()
        print("[Ouroboros] Configuración válida.")
    except EnvironmentError as e:
        print(f"\n{e}")
        return

    # ── Detectar interfaz ────────────────────────────────────────────────────
    if args.interfaz:
        interfaz = args.interfaz
        print(f"[Ouroboros] Interfaz especificada manualmente: {interfaz}")
    else:
        interfaz = detectar_interfaz()
        print(f"[Ouroboros] Interfaz detectada automáticamente: {interfaz}")

    # ── Arrancar sniffer ─────────────────────────────────────────────────────
    sniffer = OuroborosSniffer(interfaz)

    # ARP scan activo antes de iniciar monitoreo pasivo
    # Puebla dispositivos_conocidos con lo que ya está en la red
    sniffer.arp_scan()

    # ── Arrancar worker en hilo separado ─────────────────────────────────────
    # daemon=True garantiza que el hilo muere solo cuando el proceso principal
    # termina (Ctrl+C) — no hay que matarlo manualmente
    hilo_worker = threading.Thread(target=iniciar_worker, daemon=True, name="worker")
    hilo_worker.start()
    print("[Ouroboros] Worker de alertas iniciado en segundo plano.")

    # ── Monitoreo pasivo — bloquea hasta Ctrl+C ───────────────────────────────
    sniffer.iniciar()


if __name__ == "__main__":
    main()
