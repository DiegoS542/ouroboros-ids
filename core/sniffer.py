"""
core/sniffer.py
Ouroboros IDS — Módulo de captura de paquetes
Corazón del sistema. Escucha tráfico en tiempo real con Scapy,
procesa ARP para whitelist dinámica, y coordina detección con blacklist.
"""

import threading
import time
from pathlib import Path

import netifaces
from scapy.all import sniff, ARP, Ether, srp
from scapy.layers.inet import IP
from scapy.layers.dns import DNS, DNSQR

from core.blacklist import cargar_blacklist, es_peligrosa

# Archivo-señal: el dashboard lo crea cuando el admin cambia la blacklist
# o los feeds. El sniffer lo detecta y recarga en caliente sin reiniciar.
RELOAD_FLAG = Path(__file__).resolve().parent.parent / "data" / ".reload_blacklist"
from core.db_writer import (
    init_db,
    registrar_dispositivo,
    registrar_y_autorizar,
    autorizar_por_ip,
    es_autorizado,
    registrar_alerta_whitelist,
    registrar_dns,
    registrar_alerta_blacklist
)


def obtener_rango_red(interfaz):
    """
    Detecta automáticamente el rango de red de la interfaz dada.
    Retorna el rango en formato CIDR, ej: '192.168.1.0/24'
    """
    addrs = netifaces.ifaddresses(interfaz)

    if netifaces.AF_INET not in addrs:
        raise RuntimeError(f"[Ouroboros] La interfaz {interfaz} no tiene dirección IPv4.")

    ip      = addrs[netifaces.AF_INET][0]['addr']
    mascara = addrs[netifaces.AF_INET][0].get('netmask', '255.255.255.0')

    # Convertir máscara a prefijo CIDR — ej: 255.255.255.0 → 24
    prefijo = sum(bin(int(x)).count('1') for x in mascara.split('.'))

    # Calcular dirección de red — ej: 192.168.1.65 + /24 → 192.168.1.0/24
    ip_partes   = [int(x) for x in ip.split('.')]
    mask_partes = [int(x) for x in mascara.split('.')]
    red_partes  = [ip_partes[i] & mask_partes[i] for i in range(4)]
    red         = '.'.join(str(x) for x in red_partes)

    return f"{red}/{prefijo}"


def obtener_ip_mac_propias(interfaz):
    """
    Retorna la IP y MAC de la propia máquina en la interfaz dada.
    Se usa al arrancar para autorizar la máquina que corre Ouroboros.

    Se usa 17 (AF_PACKET en Linux) en lugar de netifaces.AF_LINK porque
    netifaces2 define AF_LINK = -1000 (valor genérico cross-platform) mientras
    que netifaces original usaba 17. El valor 17 es una constante del SO, no
    del paquete, por lo que funciona con cualquier versión de netifaces.
    """
    addrs = netifaces.ifaddresses(interfaz)
    ip    = addrs[netifaces.AF_INET][0]['addr']
    mac   = addrs[17][0]['addr']
    return ip, mac


def obtener_gateway():
    """
    Retorna la IP del gateway de la red (el router).
    Se usa al arrancar para autorizarlo automáticamente.

    Soporta dos formatos según la versión de netifaces instalada:
    - netifaces original: {'default': {2: ('ip', 'iface', ...)}, ...}
    - netifaces2:         {<AF_INET: 2>: [('ip', 'iface', is_default), ...], ...}
      (sin clave 'default'; el gateway está marcado con is_default=True)
    """
    gateways = netifaces.gateways()

    # Formato netifaces original
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][0]

    # Formato netifaces2 — buscar entrada IPv4 marcada como default
    for family, entries in gateways.items():
        if getattr(family, 'value', family) != 2:  # 2 = AF_INET
            continue
        for entry in entries:
            if entry[2]:  # is_default
                return entry[0]

    return None


class OuroborosSniffer:
    """
    Clase principal del sniffer.
    Encapsula estado del sistema — blacklist, interfaz, cooldowns, hilo de captura.
    """

    def __init__(self, interfaz):
        self.interfaz = interfaz

        # Inicializar base de datos
        init_db()

        # Cargar blacklist en memoria
        self.ips_peligrosas = cargar_blacklist()

        # Cooldown por MAC — evita spam de alertas del mismo dispositivo
        # Estructura: { mac: timestamp_ultima_alerta }
        self._cooldowns    = {}
        # Cooldown por IP peligrosa — una emergencia por destino cada 60 segundos
        # Estructura: { ip_peligrosa: timestamp_ultima_alerta }
        self._cooldowns_bl = {}
        self._cooldown_seg = 60
        self._lock         = threading.Lock()

        # Cola de alertas para el alert_worker de Jaime
        self.alertas_pendientes = []

        print(f"[Ouroboros] Sniffer listo en interfaz: {self.interfaz}")

    # ── ARP scan activo ──────────────────────────────────────────────────────

    def arp_scan(self):
        """
        Manda ARP requests a toda la red para descubrir dispositivos activos.
        Se ejecuta una vez al arrancar antes de iniciar el monitoreo pasivo.
        Después del scan autoriza automáticamente el gateway y la propia máquina.
        """
        try:
            rango = obtener_rango_red(self.interfaz)
            print(f"[Ouroboros] ARP scan iniciado en {rango}...")

            paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango)
            respondidos, _ = srp(paquete, iface=self.interfaz, timeout=2, verbose=0)

            nuevos = 0
            for _, respuesta in respondidos:
                ip  = respuesta[ARP].psrc
                mac = respuesta[ARP].hwsrc

                es_nuevo = registrar_dispositivo(ip, mac)
                if es_nuevo:
                    nuevos += 1
                    print(f"[ARP SCAN] Dispositivo nuevo: {ip} / {mac} — pendiente autorización")
                else:
                    print(f"[ARP SCAN] Dispositivo conocido: {ip} / {mac}")

            print(f"[Ouroboros] ARP scan completo — {len(respondidos)} dispositivos, {nuevos} nuevos.")

            # ── Autorizar gateway automáticamente ────────────────────────────
            # El router siempre es infraestructura legítima de la red
            gateway_ip = obtener_gateway()
            if gateway_ip:
                autorizar_por_ip(gateway_ip)
                print(f"[Ouroboros] Gateway autorizado automáticamente: {gateway_ip}")

            # ── Autorizar propia máquina ─────────────────────────────────────
            # La máquina que corre Ouroboros no aparece en su propio ARP scan
            ip_propia, mac_propia = obtener_ip_mac_propias(self.interfaz)
            registrar_y_autorizar(ip_propia, mac_propia)
            print(f"[Ouroboros] Máquina local autorizada: {ip_propia} / {mac_propia}")

        except Exception as e:
            print(f"[Ouroboros] Error en ARP scan: {e}")

    # ── Cooldowns ────────────────────────────────────────────────────────────

    def _en_cooldown(self, mac):
        """
        Verifica si una MAC está en periodo de cooldown.
        Evita que el mismo dispositivo genere cientos de alertas por minuto.
        Retorna True si debe ignorarse, False si puede alertar.
        """
        from datetime import datetime
        ahora = datetime.now().timestamp()

        with self._lock:
            if mac in self._cooldowns:
                if ahora - self._cooldowns[mac] < self._cooldown_seg:
                    return True  # En cooldown, ignorar
            self._cooldowns[mac] = ahora
            return False  # Fuera de cooldown, puede alertar

    def _en_cooldown_bl(self, mac_origen, ip_peligrosa):
        """
        Verifica si el par (dispositivo, IP peligrosa) está en periodo de cooldown.
        Cada dispositivo genera su propia alerta por destino — una por minuto.
        Retorna True si debe ignorarse, False si puede alertar.
        """
        from datetime import datetime
        clave = (mac_origen, ip_peligrosa)
        ahora = datetime.now().timestamp()

        with self._lock:
            if clave in self._cooldowns_bl:
                if ahora - self._cooldowns_bl[clave] < self._cooldown_seg:
                    return True
            self._cooldowns_bl[clave] = ahora
            return False

    # ── Callback principal ───────────────────────────────────────────────────

    def procesar_paquete(self, paquete):
        """
        Se ejecuta automáticamente por cada paquete que captura Scapy.
        Procesa ARP, DNS e IP en ese orden.
        """

        # ── Capa ARP — whitelist dinámica ────────────────────────────────────
        if paquete.haslayer(ARP):
            ip  = paquete[ARP].psrc
            mac = paquete[ARP].hwsrc

            if ip and mac and mac != "ff:ff:ff:ff:ff:ff":
                es_nuevo = registrar_dispositivo(ip, mac)

                if es_nuevo:
                    print(f"[ARP] Dispositivo nuevo detectado: {ip} / {mac}")
                    with self._lock:
                        self.alertas_pendientes.append({
                            "tipo": "DISPOSITIVO_NUEVO",
                            "ip":   ip,
                            "mac":  mac
                        })

        # ── Capa DNS — bitácora de sitios visitados ──────────────────────────
        if paquete.haslayer(DNS) and paquete.haslayer(DNSQR):
            dominio = paquete[DNSQR].qname.decode(errors="ignore").rstrip(".")

            if paquete.haslayer(IP):
                ip_origen = paquete[IP].src
                registrar_dns(ip_origen, dominio)
                print(f"[DNS] {ip_origen} → {dominio}")

        # ── Capa IP — validación whitelist y blacklist ───────────────────────
        if paquete.haslayer(IP):
            ip_origen  = paquete[IP].src
            ip_destino = paquete[IP].dst
            mac_origen = paquete.src if hasattr(paquete, "src") else "UNKNOWN"

            # ── Validación whitelist — cooldown por MAC ──────────────────────
            if not es_autorizado(ip_origen, mac_origen):
                if not self._en_cooldown(mac_origen):
                    detalle = f"Tráfico hacia {ip_destino}"
                    registrar_alerta_whitelist(ip_origen, mac_origen, detalle)

                    with self._lock:
                        self.alertas_pendientes.append({
                            "tipo":    "WHITELIST",
                            "ip":      ip_origen,
                            "mac":     mac_origen,
                            "detalle": detalle
                        })

                    print(f"[ALERTA] Dispositivo no autorizado: {ip_origen} / {mac_origen}")

            # ── Validación blacklist ─────────────────────────────────────────
            if es_peligrosa(ip_destino, self.ips_peligrosas):
                if not self._en_cooldown_bl(mac_origen, ip_destino):
                    registrar_alerta_blacklist(
                        ip_origen    = ip_origen,
                        mac_origen   = mac_origen,
                        ip_peligrosa = ip_destino
                    )

                    with self._lock:
                        self.alertas_pendientes.append({
                            "tipo":         "BLACKLIST",
                            "ip_origen":    ip_origen,
                            "mac_origen":   mac_origen,
                            "ip_peligrosa": ip_destino
                        })

                    print(f"[EMERGENCIA] Conexión a IP peligrosa: {ip_destino} desde {ip_origen}")

    # ── Recarga en caliente de blacklist ─────────────────────────────────────

    def _vigilar_recarga(self):
        """
        Hilo daemon: revisa cada 5 segundos si el dashboard dejó la señal
        de recarga. Si existe, vuelve a cargar la blacklist (feeds remotos +
        lista local) y reemplaza el set en memoria — sin reiniciar Ouroboros.
        """
        while True:
            time.sleep(5)
            if not RELOAD_FLAG.exists():
                continue
            try:
                nuevas = cargar_blacklist()
                # Reasignación atómica — es_peligrosa() siempre ve un set válido
                self.ips_peligrosas = nuevas
                RELOAD_FLAG.unlink(missing_ok=True)
                print(f"[Ouroboros] Blacklist recargada en caliente — "
                      f"{len(nuevas)} IPs peligrosas.")
            except Exception as e:
                print(f"[Ouroboros] Error al recargar blacklist: {e}")

    # ── Arranque ─────────────────────────────────────────────────────────────

    def iniciar(self):
        """
        Arranca la captura pasiva de paquetes.
        Esta función no termina hasta Ctrl+C.
        """
        # Hilo de recarga en caliente — muere solo al terminar el proceso
        threading.Thread(target=self._vigilar_recarga, daemon=True,
                         name="blacklist-reload").start()
        print("[Ouroboros] Vigilancia de recarga de blacklist activa (cada 5 s).")

        print(f"[Ouroboros] Iniciando captura en {self.interfaz}... (Ctrl+C para detener)")
        print("-" * 55)

        try:
            sniff(
                iface = self.interfaz,
                prn   = self.procesar_paquete,
                store = 0
            )
        except KeyboardInterrupt:
            print("\n[Ouroboros] Captura detenida por el usuario.")
