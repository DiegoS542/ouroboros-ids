import argparse
import os
import sys
import threading
import netifaces
from config.settings import validate
from core.sniffer import OuroborosSniffer
from services.worker import iniciar_worker
from dashboard.dashboard import app as dashboard_app, init_usuarios

_CLI_COMMANDS = {"status", "devices", "blacklist", "feeds", "dns", "help"}


def detectar_interfaz():
    interfaces = netifaces.interfaces()

    for interfaz in interfaces:
        if interfaz == "lo":
            continue

        addrs = netifaces.ifaddresses(interfaz)
        if netifaces.AF_INET in addrs:
            return interfaz

    return "lo"


def main():
    if len(sys.argv) > 1 and sys.argv[1] in _CLI_COMMANDS:
        from cli import despachar
        despachar()
        return

    if os.geteuid() != 0:
        print("Error: Ouroboros requiere privilegios de administrador.")
        print("Ejecuta: sudo ouroboros")
        sys.exit(1)

    print("""
    ╔═══════════════════════════════════════════╗
    ║           OUROBOROS IDS v1.0              ║
    ║     Sistema de Detección de Intrusos      ║
    ║                                           ║
    ║  "El ciclo eterno de los ataques          ║
    ║        y las amenazas"                    ║
    ╚═══════════════════════════════════════════╝
    """)

    parser = argparse.ArgumentParser(description="Ouroboros IDS — Sistema de Detección de Intrusos")
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface to monitor (e.g. wlan0, eth0). Auto-detected if not specified."
    )
    args = parser.parse_args()

    print("[Ouroboros] Validando configuración...")
    try:
        validate()
        print("[Ouroboros] Configuración válida.")
    except EnvironmentError as e:
        print(f"\n{e}")
        return

    if args.interface:
        interfaz = args.interface
        print(f"[Ouroboros] Interfaz especificada manualmente: {interfaz}")
    else:
        interfaz = detectar_interfaz()
        print(f"[Ouroboros] Interfaz detectada automáticamente: {interfaz}")

    sniffer = OuroborosSniffer(interfaz)

    sniffer.arp_scan()

    hilo_worker = threading.Thread(target=iniciar_worker, daemon=True, name="worker")
    hilo_worker.start()
    print("[Ouroboros] Worker de alertas iniciado en segundo plano.")

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    pwd_inicial = init_usuarios()
    hilo_dashboard = threading.Thread(
        target=lambda: dashboard_app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False),
        daemon=True, name="dashboard"
    )
    hilo_dashboard.start()
    ip_red = netifaces.ifaddresses(interfaz)[netifaces.AF_INET][0]['addr']
    sep = "─" * 48
    print(f"\n  {sep}")
    print(f"  [Dashboard] Local:     http://127.0.0.1:5000")
    print(f"  [Dashboard] Red local: http://{ip_red}:5000")
    if pwd_inicial:
        print(f"  [Dashboard] Usuario:    admin")
        print(f"  [Dashboard] Contraseña: {pwd_inicial}")
    print(f"  {sep}")
    if pwd_inicial:
        print(f"\n  ⚠ Primer arranque — cambia la contraseña desde el dashboard antes de usar el sistema.")
    print()

    sniffer.iniciar()


if __name__ == "__main__":
    main()
