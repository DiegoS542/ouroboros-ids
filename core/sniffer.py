"""
core/sniffer.py
Ouroboros IDS — Módulo de captura de paquetes
Corazón del sistema. Escucha tráfico en tiempo real con Scapy
y coordina la detección con whitelist, blacklist y base de datos.
"""

import threading
from scapy.all import sniff, ARP
from scapy.layers.inet import IP
from scapy.layers.dns import DNS, DNSQR

from core.whitelist import cargar_whitelist, es_autorizado
from core.blacklist import cargar_blacklist, es_peligrosa
from core.db_writer import (
    init_db,
    registrar_alerta_whitelist,
    registrar_dns,
    registrar_alerta_blacklist
)


class OuroborosSniffer:
    """
    Clase principal del sniffer.
    Encapsula el estado del sistema — listas cargadas, interfaz, hilo de captura.
    """

    def __init__(self, interfaz):
        """
        interfaz — nombre de tu interfaz de red (ej. 'wlan0', 'eth0')
        Se carga al arrancar y se mantiene en memoria durante toda la sesión.
        """
        self.interfaz = interfaz

        # Inicializar base de datos
        init_db()

        # Cargar listas en memoria — se leen una vez al arrancar
        # Si quieres recargarlas sin reiniciar el sistema, llama a recargar_listas()
        self.ips_autorizadas, self.macs_autorizadas = cargar_whitelist()
        self.ips_peligrosas = cargar_blacklist()

        # Cola de alertas pendientes para el módulo de correo (Jaime)
        # El alert_worker de services/ monitorea esta cola
        self.alertas_pendientes = []
        self._lock = threading.Lock()

        print(f"[Ouroboros] Sniffer listo en interfaz: {self.interfaz}")

    # ── Métodos de recarga en caliente ──────────────────────────────────────

    def recargar_listas(self):
        """
        Recarga whitelist y blacklist sin detener el sniffer.
        Útil cuando el admin agrega un dispositivo desde el dashboard.
        """
        self.ips_autorizadas, self.macs_autorizadas = cargar_whitelist()
        self.ips_peligrosas = cargar_blacklist()
        print("[Ouroboros] Listas recargadas en caliente.")

    # ── Callback principal ───────────────────────────────────────────────────

    def procesar_paquete(self, paquete):
        """
        Se ejecuta automáticamente por cada paquete que captura Scapy.
        Este es el corazón del IDS — aquí vive toda la lógica de detección.
        """

        # ── Módulo DNS — bitácora de sitios visitados ────────────────────────
        # Si el paquete es una consulta DNS (alguien abriendo un sitio web)
        # extraemos el dominio y lo registramos en la bitácora
        if paquete.haslayer(DNS) and paquete.haslayer(DNSQR):
            # DNSQR es la subcapa de "pregunta" DNS
            # qname contiene el dominio consultado, ej: b'youtube.com.'
            dominio = paquete[DNSQR].qname.decode(errors="ignore").rstrip(".")

            # Solo registramos si el paquete también tiene capa IP
            # (para saber quién hizo la consulta)
            if paquete.haslayer(IP):
                ip_origen = paquete[IP].src
                registrar_dns(ip_origen, dominio)
                print(f"[DNS] {ip_origen} → {dominio}")

        # ── Módulo IP — whitelist y blacklist ────────────────────────────────
        # Si el paquete tiene capa IP podemos ver origen y destino
        if paquete.haslayer(IP):
            ip_origen  = paquete[IP].src
            ip_destino = paquete[IP].dst

            # Extraer MAC origen de la capa Ethernet
            # Si no tiene capa Ethernet (paquete tunelizado) usamos "UNKNOWN"
            mac_origen = paquete.src if hasattr(paquete, "src") else "UNKNOWN"

            # ── Validación whitelist ─────────────────────────────────────────
            # ¿Este dispositivo está autorizado en la red?
            if not es_autorizado(ip_origen, mac_origen,
                                  self.ips_autorizadas, self.macs_autorizadas):

                detalle = f"Tráfico hacia {ip_destino}"
                registrar_alerta_whitelist(ip_origen, mac_origen, detalle)

                # Encolar alerta para que el mailer de Jaime la procese
                with self._lock:
                    self.alertas_pendientes.append({
                        "tipo":   "WHITELIST",
                        "ip":     ip_origen,
                        "mac":    mac_origen,
                        "detalle": detalle
                    })

                print(f"[ALERTA] Dispositivo no autorizado: {ip_origen} / {mac_origen}")

            # ── Validación blacklist ─────────────────────────────────────────
            # ¿El destino es una IP peligrosa?
            if es_peligrosa(ip_destino, self.ips_peligrosas):

                registrar_alerta_blacklist(
                    ip_origen    = ip_origen,
                    mac_origen   = mac_origen,
                    ip_peligrosa = ip_destino
                    # tipo_riesgo, score, ISP, correo_abuso
                    # los completa abuse_api.py de Jaime después
                )

                # Encolar alerta de emergencia
                with self._lock:
                    self.alertas_pendientes.append({
                        "tipo":        "BLACKLIST",
                        "ip_origen":   ip_origen,
                        "mac_origen":  mac_origen,
                        "ip_peligrosa": ip_destino
                    })

                print(f"[EMERGENCIA] Conexión a IP peligrosa: {ip_destino} desde {ip_origen}")

    # ── Arranque del sniffer ─────────────────────────────────────────────────

    def iniciar(self):
        """
        Arranca la captura de paquetes. Esta función no termina nunca —
        corre hasta que el usuario presiona Ctrl+C.
        """
        print(f"[Ouroboros] Iniciando captura en {self.interfaz}... (Ctrl+C para detener)")
        print("-" * 55)

        try:
            # store=0 — no guardar paquetes en RAM (importante para rendimiento)
            # prn — función callback que se llama por cada paquete
            # iface — interfaz de red donde escuchar
            sniff(
                iface  = self.interfaz,
                prn    = self.procesar_paquete,
                store  = 0
            )
        except KeyboardInterrupt:
            print("\n[Ouroboros] Captura detenida por el usuario.")
