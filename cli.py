"""
cli.py
Ouroboros IDS — Interfaz de administración en línea de comandos

Comandos disponibles:
    devices  list                  — lista dispositivos conocidos
    devices  authorize <mac>       — autoriza un dispositivo (aplica en caliente)
    devices  block <mac>           — revoca autorización (aplica en caliente)
    devices  clear                 — elimina todos los dispositivos conocidos

    blacklist list                 — muestra IPs en blacklist.txt
    blacklist add <ip>             — agrega IP a blacklist.txt
    blacklist remove <ip>          — elimina IP de blacklist.txt

    feeds list                     — lista feeds de IPs peligrosas
    feeds add <nombre> <url>       — registra un nuevo feed
    feeds enable <id>              — activa un feed por id
    feeds disable <id>             — desactiva un feed por id

    status                         — resumen general de contadores
    dns <ip>                       — últimas 20 consultas DNS de una IP

Uso (instalado vía pip install -e .):
    ouroboros status
    ouroboros devices list
    ouroboros blacklist add 1.2.3.4

Uso directo:
    python cli.py status

No requiere sudo — solo accede a SQLite y archivos locales.
"""

import argparse
import ipaddress
import sqlite3
import sys
from pathlib import Path

from config.settings import DB_PATH, BASE_DIR
from core import db_writer

BLACKLIST_PATH = BASE_DIR / "data" / "blacklist.txt"
RELOAD_FLAG    = BASE_DIR / "data" / ".reload_blacklist"


def _señalar_recarga():
    """Toca el archivo-señal para que el sniffer recargue la blacklist en ~5 s."""
    try:
        RELOAD_FLAG.touch()
    except OSError as e:
        print(f"Advertencia: no se pudo crear la señal de recarga ({e}).")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _conn():
    """Abre conexión SQLite con acceso a columnas por nombre."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _fecha(iso):
    """Formatea timestamp ISO a 'YYYY-MM-DD HH:MM:SS'. Retorna '—' si es None."""
    return (iso or "—")[:19].replace("T", " ")


def _salir_error(msg):
    """Imprime error y termina con código 1."""
    print(f"Error: {msg}")
    sys.exit(1)


# ── devices list ──────────────────────────────────────────────────────────────

def cmd_devices_list(_args):
    with _conn() as conn:
        filas = conn.execute(
            "SELECT ip, mac, ultimo_visto, autorizado "
            "FROM dispositivos_conocidos ORDER BY ultimo_visto DESC"
        ).fetchall()

    if not filas:
        print("Sin dispositivos registrados todavía.")
        return

    col_ip  = max(len("IP"),  max(len(f["ip"])  for f in filas))
    col_mac = max(len("MAC"), max(len(f["mac"]) for f in filas))
    ancho   = col_ip + col_mac + 20 + 10 + 4

    print(f"{'IP':<{col_ip}}  {'MAC':<{col_mac}}  {'ÚLTIMO VISTO':<20}  ESTADO")
    print("─" * ancho)
    for f in filas:
        mac    = f["mac"].upper()
        estado = "✓ autorizado" if f["autorizado"] else "✗ pendiente"
        print(f"{f['ip']:<{col_ip}}  {mac:<{col_mac}}  {_fecha(f['ultimo_visto']):<20}  {estado}")


# ── devices authorize ─────────────────────────────────────────────────────────

def cmd_devices_authorize(args):
    mac = args.mac.strip()
    with _conn() as conn:
        fila = conn.execute(
            "SELECT mac FROM dispositivos_conocidos WHERE UPPER(mac) = UPPER(?)", (mac,)
        ).fetchone()

    if not fila:
        _salir_error(f"no se encontró ningún dispositivo con MAC {mac}.")

    db_writer.autorizar_dispositivo(fila["mac"])
    print(f"✓ Dispositivo {fila['mac'].upper()} autorizado.")


# ── devices block ─────────────────────────────────────────────────────────────

def cmd_devices_block(args):
    mac = args.mac.strip()
    with _conn() as conn:
        fila = conn.execute(
            "SELECT mac FROM dispositivos_conocidos WHERE UPPER(mac) = UPPER(?)", (mac,)
        ).fetchone()

        if not fila:
            _salir_error(f"no se encontró ningún dispositivo con MAC {mac}.")

        conn.execute(
            "UPDATE dispositivos_conocidos SET autorizado = 0 WHERE UPPER(mac) = UPPER(?)",
            (mac,)
        )
        conn.commit()

    print(f"✓ Autorización de {fila['mac'].upper()} revocada.")


# ── devices clear ─────────────────────────────────────────────────────────────

def cmd_devices_clear(_args):
    with _conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM dispositivos_conocidos"
        ).fetchone()[0]

    if total == 0:
        print("No hay dispositivos registrados.")
        return

    resp = input(f"⚠ Se eliminarán {total} dispositivos conocidos. ¿Continuar? [y/N]: ").strip().lower()
    if resp != "y":
        print("Cancelado.")
        return

    with _conn() as conn:
        conn.execute("DELETE FROM dispositivos_conocidos")
        conn.commit()

    print("✓ Lista de dispositivos limpiada.")
    print("⚠ Reiniciar Ouroboros para repoblar via ARP scan.")


# ── blacklist helpers ─────────────────────────────────────────────────────────

def _leer_blacklist_raw():
    """
    Lee blacklist.txt línea por línea.
    Retorna lista de tuplas (linea_original, ip_parseada_o_None).
    """
    if not BLACKLIST_PATH.exists():
        return []
    resultado = []
    with open(BLACKLIST_PATH) as f:
        for linea in f:
            stripped = linea.strip()
            if not stripped or stripped.startswith("#"):
                resultado.append((linea, None))
            else:
                try:
                    ipaddress.ip_address(stripped)
                    resultado.append((linea, stripped))
                except ValueError:
                    resultado.append((linea, None))
    return resultado


def _ips_blacklist():
    """Retorna set de IPs activas en blacklist.txt."""
    return {ip for _, ip in _leer_blacklist_raw() if ip}


# ── blacklist list ────────────────────────────────────────────────────────────

def cmd_blacklist_list(_args):
    ips = sorted(_ips_blacklist())
    if not ips:
        print("La lista negra local está vacía.")
        return

    print("IPs en lista negra local")
    print("─" * 20)
    for ip in ips:
        print(ip)
    print(f"\n{len(ips)} IP(s) en total")


# ── blacklist add ─────────────────────────────────────────────────────────────

def cmd_blacklist_add(args):
    ip = args.ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        _salir_error(f"'{ip}' no es una dirección IP válida.")

    if ip in _ips_blacklist():
        _salir_error(f"la IP {ip} ya está en la lista negra.")

    with open(BLACKLIST_PATH, "a") as f:
        f.write(f"{ip}\n")

    _señalar_recarga()
    print(f"✓ IP {ip} agregada a blacklist.txt — el sniffer la aplicará en ~5 s.")


# ── blacklist remove ──────────────────────────────────────────────────────────

def cmd_blacklist_remove(args):
    ip = args.ip.strip()
    entradas = _leer_blacklist_raw()

    if ip not in {p for _, p in entradas if p}:
        _salir_error(f"la IP {ip} no está en la lista negra.")

    # Reescribe el archivo conservando comentarios y demás líneas
    nuevas = [linea for linea, parsed in entradas if parsed != ip]
    with open(BLACKLIST_PATH, "w") as f:
        f.writelines(nuevas)

    _señalar_recarga()
    print(f"✓ IP {ip} eliminada de blacklist.txt — el sniffer la aplicará en ~5 s.")


# ── feeds list ────────────────────────────────────────────────────────────────

def cmd_feeds_list(_args):
    with _conn() as conn:
        filas = conn.execute(
            "SELECT id, nombre, url, activo, ultimo_update "
            "FROM feed_sources ORDER BY id"
        ).fetchall()

    if not filas:
        print("Sin feeds registrados.")
        return

    col_nombre = max(len("NOMBRE"), max(len(f["nombre"]) for f in filas))

    print(f"{'ID':<4}  {'NOMBRE':<{col_nombre}}  {'ACTIVO':<7}  {'ÚLTIMO UPDATE':<20}  URL")
    print("─" * (4 + col_nombre + 7 + 20 + 50 + 10))
    for f in filas:
        activo = "✓" if f["activo"] else "✗"
        update = _fecha(f["ultimo_update"]) if f["ultimo_update"] else "—"
        url    = f["url"] if len(f["url"]) <= 45 else f["url"][:42] + "..."
        print(f"{f['id']:<4}  {f['nombre']:<{col_nombre}}  {activo:<7}  {update:<20}  {url}")


# ── feeds add ─────────────────────────────────────────────────────────────────

def cmd_feeds_add(args):
    nombre = args.nombre.strip()
    url    = args.url.strip()

    if not url.startswith(("http://", "https://")):
        _salir_error(f"'{url}' no es una URL válida (debe comenzar con http:// o https://).")

    with _conn() as conn:
        try:
            conn.execute(
                "INSERT INTO feed_sources (nombre, url, activo) VALUES (?, ?, 1)",
                (nombre, url)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            _salir_error(f"la URL '{url}' ya está registrada.")

    _señalar_recarga()
    print(f"✓ Feed '{nombre}' registrado y activado — el sniffer lo descargará en ~5 s.")


# ── feeds enable / disable ────────────────────────────────────────────────────

def _feed_existe(conn, feed_id):
    return conn.execute(
        "SELECT id FROM feed_sources WHERE id = ?", (feed_id,)
    ).fetchone() is not None


def cmd_feeds_enable(args):
    with _conn() as conn:
        fila = conn.execute(
            "SELECT nombre FROM feed_sources WHERE id = ?", (args.id,)
        ).fetchone()
        if not fila:
            _salir_error(f"no existe un feed con id {args.id}.")
        conn.execute("UPDATE feed_sources SET activo = 1 WHERE id = ?", (args.id,))
        conn.commit()
    _señalar_recarga()
    print(f"✓ Feed '{fila['nombre']}' activado — el sniffer lo aplicará en ~5 s.")


def cmd_feeds_disable(args):
    with _conn() as conn:
        fila = conn.execute(
            "SELECT nombre FROM feed_sources WHERE id = ?", (args.id,)
        ).fetchone()
        if not fila:
            _salir_error(f"no existe un feed con id {args.id}.")
        conn.execute("UPDATE feed_sources SET activo = 0 WHERE id = ?", (args.id,))
        conn.commit()
    _señalar_recarga()
    print(f"✓ Feed '{fila['nombre']}' desactivado — el sniffer lo aplicará en ~5 s.")


# ── status ────────────────────────────────────────────────────────────────────

def cmd_status(_args):
    with _conn() as conn:
        total_disp  = conn.execute("SELECT COUNT(*) FROM dispositivos_conocidos").fetchone()[0]
        autorizados = conn.execute(
            "SELECT COUNT(*) FROM dispositivos_conocidos WHERE autorizado = 1"
        ).fetchone()[0]
        alertas_wl  = conn.execute("SELECT COUNT(*) FROM alertas_whitelist").fetchone()[0]
        alertas_bl  = conn.execute("SELECT COUNT(*) FROM alertas_blacklist").fetchone()[0]
        entradas_dns = conn.execute("SELECT COUNT(*) FROM bitacora_dns").fetchone()[0]
        feeds_activos = conn.execute(
            "SELECT COUNT(*) FROM feed_sources WHERE activo = 1"
        ).fetchone()[0]

    linea = "─" * 33
    print(linea)
    print("  Ouroboros IDS — Estado")
    print(linea)
    print(f"  {'Dispositivos conocidos':<22} {total_disp:>5}")
    print(f"  {'Autorizados':<22} {autorizados:>5}")
    print(f"  {'Alertas whitelist':<22} {alertas_wl:>5}")
    print(f"  {'Alertas blacklist':<22} {alertas_bl:>5}")
    print(f"  {'Entradas DNS':<22} {entradas_dns:>5}")
    print(f"  {'Feeds activos':<22} {feeds_activos:>5}")
    print(linea)


# ── dns ───────────────────────────────────────────────────────────────────────

def cmd_dns(args):
    ip = args.ip.strip()
    with _conn() as conn:
        # Agrupa por dominio para evitar duplicados (el sniffer captura
        # pregunta y respuesta del mismo DNS). Muestra la visita más reciente.
        filas = conn.execute(
            "SELECT dominio, MAX(timestamp) AS ultima_vez "
            "FROM bitacora_dns WHERE ip_origen = ? "
            "GROUP BY dominio ORDER BY ultima_vez DESC LIMIT 20",
            (ip,)
        ).fetchall()

    if not filas:
        print(f"Sin registros DNS para la IP {ip}.")
        return

    col_dom = max(len("DOMINIO"), max(len(f["dominio"]) for f in filas))
    print(f"Consultas DNS — {ip}")
    print(f"{'DOMINIO':<{col_dom}}  ÚLTIMA VISITA")
    print("─" * (col_dom + 22))
    for f in filas:
        print(f"{f['dominio']:<{col_dom}}  {_fecha(f['ultima_vez'])}")


# ── Parseo de argumentos ──────────────────────────────────────────────────────

def _build_parser():
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Ouroboros IDS — Interfaz de administración en línea de comandos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="comando", metavar="comando")
    sub.required = True

    # ── devices ──────────────────────────────────────────────────────────────
    p_dev = sub.add_parser("devices", help="Gestión de dispositivos detectados en la red")
    sub_dev = p_dev.add_subparsers(dest="subcomando", metavar="subcomando")
    sub_dev.required = True

    sub_dev.add_parser("list", help="Lista dispositivos conocidos")

    p_auth = sub_dev.add_parser("authorize", help="Autoriza un dispositivo por MAC")
    p_auth.add_argument("mac", help="Dirección MAC (ej: AA:BB:CC:DD:EE:FF)")

    p_block = sub_dev.add_parser("block", help="Revoca la autorización de un dispositivo")
    p_block.add_argument("mac", help="Dirección MAC (ej: AA:BB:CC:DD:EE:FF)")

    sub_dev.add_parser("clear", help="Elimina todos los dispositivos conocidos (con confirmación)")

    # ── blacklist ─────────────────────────────────────────────────────────────
    p_bl = sub.add_parser("blacklist", help="Gestión de la lista negra local (blacklist.txt)")
    sub_bl = p_bl.add_subparsers(dest="subcomando", metavar="subcomando")
    sub_bl.required = True

    sub_bl.add_parser("list", help="Muestra las IPs en blacklist.txt")

    p_bl_add = sub_bl.add_parser("add", help="Agrega una IP a blacklist.txt")
    p_bl_add.add_argument("ip", help="Dirección IP a agregar")

    p_bl_rem = sub_bl.add_parser("remove", help="Elimina una IP de blacklist.txt")
    p_bl_rem.add_argument("ip", help="Dirección IP a eliminar")

    # ── feeds ─────────────────────────────────────────────────────────────────
    p_feeds = sub.add_parser("feeds", help="Gestión de feeds de IPs peligrosas")
    sub_feeds = p_feeds.add_subparsers(dest="subcomando", metavar="subcomando")
    sub_feeds.required = True

    sub_feeds.add_parser("list", help="Lista los feeds registrados")

    p_feeds_add = sub_feeds.add_parser("add", help="Registra un nuevo feed")
    p_feeds_add.add_argument("nombre", help="Nombre descriptivo del feed")
    p_feeds_add.add_argument("url", help="URL del feed (http/https)")

    p_feeds_en = sub_feeds.add_parser("enable", help="Activa un feed por id")
    p_feeds_en.add_argument("id", type=int, help="ID del feed")

    p_feeds_dis = sub_feeds.add_parser("disable", help="Desactiva un feed por id (sin borrarlo)")
    p_feeds_dis.add_argument("id", type=int, help="ID del feed")

    # ── status ────────────────────────────────────────────────────────────────
    sub.add_parser("status", help="Resumen general: contadores de todas las tablas")

    # ── dns ───────────────────────────────────────────────────────────────────
    p_dns = sub.add_parser("dns", help="Últimas 20 consultas DNS de una IP específica")
    p_dns.add_argument("ip", help="Dirección IP a consultar")

    return parser


# ── Tabla de dispatch ─────────────────────────────────────────────────────────

_DISPATCH = {
    "devices": {
        "list":      cmd_devices_list,
        "authorize": cmd_devices_authorize,
        "block":     cmd_devices_block,
        "clear":     cmd_devices_clear,
    },
    "blacklist": {
        "list":   cmd_blacklist_list,
        "add":    cmd_blacklist_add,
        "remove": cmd_blacklist_remove,
    },
    "feeds": {
        "list":    cmd_feeds_list,
        "add":     cmd_feeds_add,
        "enable":  cmd_feeds_enable,
        "disable": cmd_feeds_disable,
    },
}


def despachar():
    """
    Punto de entrada público. Parsea sys.argv y ejecuta el comando.
    Llamado por ouroboros.main() cuando detecta un subcomando de administración,
    y también directamente cuando se invoca cli.py standalone.
    No llama a sys.exit() al terminar normalmente — solo _salir_error() en errores.
    """
    parser = _build_parser()
    args   = parser.parse_args()

    if args.comando in _DISPATCH:
        _DISPATCH[args.comando][args.subcomando](args)
    elif args.comando == "status":
        cmd_status(args)
    elif args.comando == "dns":
        cmd_dns(args)


def main():
    """Wrapper para uso standalone: python cli.py <comando>"""
    despachar()


if __name__ == "__main__":
    main()
