"""
ouroboros.py
Ouroboros IDS — Punto de entrada principal
Autor: Diego

Arranca el sistema completo:
    1. Valida que todas las variables de entorno estén configuradas
    2. Detecta la interfaz de red disponible
    3. Inicializa el sniffer
    4. Arranca tres hilos en paralelo:
         Hilo 1 — sniffer (captura paquetes)
         Hilo 2 — worker (monitorea SQLite y manda correos)
         Hilo 3 — dashboard (Flask en http://0.0.0.0:5000)

Uso:
    sudo venv/bin/python ouroboros.py
    sudo venv/bin/python ouroboros.py --interfaz eth0
"""

import argparse
import sys
import threading
import netifaces
from config.settings import validate
from core.sniffer import OuroborosSniffer
from services.worker import iniciar_worker
from dashboard.dashboard import app as dashboard_app, init_usuarios

# Subcomandos que pertenecen al CLI de administración.
# Cualquier otro argumento (--interfaz, nada) arranca el IDS.
_CLI_COMMANDS = {"status", "devices", "blacklist", "feeds", "dns"}


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
    # ── Dispatch al CLI de administración ────────────────────────────────────
    # Si el primer argumento es un subcomando conocido del CLI, delegar y salir.
    # Así `ouroboros status`, `ouroboros devices list`, etc. funcionan sin sudo.
    if len(sys.argv) > 1 and sys.argv[1] in _CLI_COMMANDS:
        from cli import despachar
        despachar()
        return

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
    hilo_worker = threading.Thread(target=iniciar_worker, daemon=True, name="worker")
    hilo_worker.start()
    print("[Ouroboros] Worker de alertas iniciado en segundo plano.")

    # ── Arrancar dashboard en hilo separado ──────────────────────────────────
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    init_usuarios()
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
    print(f"  {sep}\n")

    # ── Monitoreo pasivo — bloquea hasta Ctrl+C ───────────────────────────────
    sniffer.iniciar()


if __name__ == "__main__":
    main()
