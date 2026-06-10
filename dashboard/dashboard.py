"""
dashboard.py
Ouroboros IDS — Dashboard web de administración
Interfaz Flask para consultar las vistas de la base de datos y
administrar el sistema sin tocar archivos manualmente.

Seguridad (Identificación / Autenticación / Autorización):
    - Login obligatorio al acceder (usuario + contraseña del .env).
    - Al autenticarse se emite un JWT firmado (HS256) con el claim rol=admin
      y expiración de 30 minutos, guardado en cookie HttpOnly.
    - Toda vista y acción (incluido el cambio del correo de alertas)
      valida el token antes de ejecutarse.

Vistas:
    /login        Inicio de sesión (emite el JWT)
    /             Resumen general (contadores y últimas alertas)
    /dispositivos Dispositivos detectados + autorización por MAC (directo a BD)
    /alertas      Alertas de dispositivos no autorizados (Capa 2/3)
    /dns          Bitácora de dominios visitados
    /blacklist    Lista negra local + feeds remotos + detecciones forenses
    /config       Cambio del correo admin que recibe las alertas
    /logout       Cierra sesión (borra el token)

Uso (desde la raíz del proyecto):
    pip install flask python-dotenv PyJWT
    python dashboard.py        →  http://127.0.0.1:5000

Variables requeridas en .env:
    DASHBOARD_USER=admin
    DASHBOARD_PASSWORD=tu_clave
    JWT_SECRET=(se genera solo si falta)

Funciona aunque el sniffer NO esté corriendo: solo lee la base SQLite.
Para probar con datos falsos:  python seed_demo.py
"""

import html
import re
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

# El dashboard vive en /dashboard — agregar la raíz del proyecto al path
# para que los imports de config/ y core/ funcionen desde cualquier lugar.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jwt  # PyJWT
from flask import (Flask, render_template_string, request, redirect,
                   url_for, flash, make_response)
from werkzeug.security import generate_password_hash, check_password_hash

from config.settings import DB_PATH, BASE_DIR
from core import db_writer
from core.feed_updater import BLACKLIST_PATH, _cargar_blacklist_local

ENV_PATH = BASE_DIR / ".env"

# Archivo-señal: al tocarlo, el sniffer recarga la blacklist en caliente
# (lo vigila un hilo en core/sniffer.py cada 5 segundos).
RELOAD_FLAG = BASE_DIR / "data" / ".reload_blacklist"


def señalar_recarga():
    """Pide al sniffer que recargue la blacklist sin reiniciar Ouroboros."""
    try:
        RELOAD_FLAG.touch()
    except OSError as e:
        print(f"[Dashboard] No se pudo crear la señal de recarga: {e}")

app = Flask(__name__)
app.secret_key = "ouroboros-dashboard"  # solo para mensajes flash locales

TOKEN_MINUTOS = 30  # vigencia del JWT


# ── Manejo del .env ──────────────────────────────────────────────────────────

def leer_env_var(clave):
    """Lee el valor actual de una variable directamente del .env."""
    if not ENV_PATH.exists():
        return ""
    for linea in ENV_PATH.read_text().splitlines():
        if linea.strip().startswith(f"{clave}="):
            return linea.split("=", 1)[1].strip()
    return ""


def escribir_env_var(clave, valor):
    """Actualiza (o agrega) una variable en el .env sin tocar las demás."""
    lineas = ENV_PATH.read_text().splitlines() if ENV_PATH.exists() else []
    encontrada = False
    for i, linea in enumerate(lineas):
        if linea.strip().startswith(f"{clave}="):
            lineas[i] = f"{clave}={valor}"
            encontrada = True
            break
    if not encontrada:
        lineas.append(f"{clave}={valor}")
    ENV_PATH.write_text("\n".join(lineas) + "\n")


def obtener_jwt_secret():
    """
    Lee JWT_SECRET del .env. Si no existe, genera uno aleatorio y lo
    persiste — así el secreto nunca queda hardcoded en el código.
    """
    secreto = leer_env_var("JWT_SECRET")
    if not secreto:
        secreto = secrets.token_hex(32)
        escribir_env_var("JWT_SECRET", secreto)
        print("[Ouroboros] JWT_SECRET generado y guardado en .env")
    return secreto


JWT_SECRET = obtener_jwt_secret()


# ── JWT: emisión y validación ────────────────────────────────────────────────

ROLES_VALIDOS = ("admin", "operador")


def crear_token(usuario, rol, cambiar_pwd=False):
    """Emite un JWT firmado con el rol del usuario y expiración."""
    payload = {
        "sub": usuario,                          # identificación
        "rol": rol,                              # autorización
        "pwd": 1 if cambiar_pwd else 0,          # debe cambiar contraseña
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTOS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def validar_token():
    """Retorna el payload si la cookie trae un JWT válido, o None."""
    token = request.cookies.get("token")
    if not token:
        return None
    try:
        datos = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if datos.get("rol") not in ROLES_VALIDOS:
            return None
        return datos
    except jwt.InvalidTokenError:
        return None


def requiere_token(f):
    """
    Decorador: exige JWT válido o redirige al login.
    Si el token trae la marca de contraseña temporal, obliga a cambiarla
    antes de poder usar cualquier otra vista.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        datos = validar_token()
        if datos is None:
            return redirect(url_for("login"))
        if datos.get("pwd") == 1 and request.endpoint not in ("cambiar_password", "logout"):
            return redirect(url_for("cambiar_password"))
        return f(*args, **kwargs)
    return wrapper


def requiere_admin(f):
    """Decorador: además del token, exige rol admin (autorización)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        datos = validar_token()
        if datos is None:
            return redirect(url_for("login"))
        if datos.get("rol") != "admin":
            flash("Se requiere rol de administrador para esa acción.")
            return redirect(url_for("resumen"))
        if datos.get("pwd") == 1:
            return redirect(url_for("cambiar_password"))
        return f(*args, **kwargs)
    return wrapper


# ── Acceso a datos (solo lectura sobre la misma BD del IDS) ──────────────────

def query(sql, params=()):
    """Consulta de solo lectura. Retorna filas como diccionarios."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def scalar(sql, params=()):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else 0


# ── Usuarios: tabla, seed inicial y helpers ──────────────────────────────────

def init_usuarios():
    """
    Crea la tabla de usuarios si no existe. Si está vacía, genera una
    contraseña aleatoria para el admin, la hashea y la persiste.
    Retorna la contraseña en texto plano solo en ese primer arranque,
    None si el admin ya existía. El usuario está marcado para cambiar
    la contraseña en el primer login.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario       TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                rol           TEXT NOT NULL DEFAULT 'operador',
                cambiar_pwd   INTEGER DEFAULT 1,
                creado        TEXT NOT NULL
            )
        """)
        conn.commit()

        if conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
            clave = secrets.token_urlsafe(10)
            conn.execute(
                """INSERT INTO usuarios (usuario, password_hash, rol, cambiar_pwd, creado)
                   VALUES (?, ?, 'admin', 1, ?)""",
                ("admin", generate_password_hash(clave),
                 datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            return clave  # solo existe en texto plano este instante

    return None


def buscar_usuario(usuario):
    """Retorna el registro del usuario o None."""
    filas = query("SELECT * FROM usuarios WHERE usuario = ?", (usuario,))
    return filas[0] if filas else None


# ── Gestión de blacklist.txt local ───────────────────────────────────────────
# Los feeds remotos los descarga core/feed_updater al arrancar el sniffer;
# aquí solo se administra la lista local y las fuentes de feeds (tabla).

def agregar_ip_local(ip):
    """Agrega una IP a blacklist.txt. Retorna False si ya estaba."""
    ip = ip.strip()
    if ip in _cargar_blacklist_local():
        return False
    with open(BLACKLIST_PATH, "a") as f:
        f.write(f"{ip}\n")
    return True


def quitar_ip_local(ip):
    """Elimina una IP de blacklist.txt. Retorna True si existía."""
    ip = ip.strip()
    with open(BLACKLIST_PATH, "r") as f:
        lineas = f.readlines()
    nuevas = [l for l in lineas if l.strip() != ip]
    if len(nuevas) == len(lineas):
        return False
    with open(BLACKLIST_PATH, "w") as f:
        f.writelines(nuevas)
    return True


# ── Plantilla base ───────────────────────────────────────────────────────────

BASE = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Ouroboros IDS — {{ titulo }}</title>
<style>
  :root {
    --bg:#0d1117; --panel:#161b22; --border:#30363d; --txt:#e6edf3;
    --dim:#8b949e; --green:#3fb950; --red:#f85149; --yellow:#d29922;
    --blue:#58a6ff; --accent:#7c3aed;
  }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--txt);
         font:14px/1.5 'Segoe UI', system-ui, sans-serif; }
  header { display:flex; align-items:center; gap:16px; padding:14px 24px;
           background:var(--panel); border-bottom:1px solid var(--border); }
  header h1 { font-size:18px; }
  header h1 span { color:var(--accent); }
  nav { display:flex; gap:4px; margin-left:auto; flex-wrap:wrap; }
  nav a { color:var(--dim); text-decoration:none; padding:6px 12px;
          border-radius:6px; font-size:13px; }
  nav a:hover { color:var(--txt); background:var(--border); }
  nav a.activa { color:var(--txt); background:var(--accent); }
  nav a.salir { color:var(--red); }
  main { max-width:1100px; margin:24px auto; padding:0 24px; }
  h2 { font-size:16px; margin-bottom:14px; color:var(--blue); }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
           gap:14px; margin-bottom:26px; }
  .card { background:var(--panel); border:1px solid var(--border);
          border-radius:10px; padding:16px; }
  .card .num { font-size:30px; font-weight:700; }
  .card .lbl { color:var(--dim); font-size:12px; text-transform:uppercase; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  th, td { padding:9px 12px; text-align:left; border-bottom:1px solid var(--border); }
  th { background:#1c2129; color:var(--dim); font-size:12px;
       text-transform:uppercase; }
  tr:last-child td { border-bottom:none; }
  .ok    { color:var(--green); font-weight:600; }
  .mal   { color:var(--red);   font-weight:600; }
  .warn  { color:var(--yellow); }
  .badge { padding:2px 8px; border-radius:10px; font-size:12px; font-weight:600; }
  .badge.rojo  { background:rgba(248,81,73,.15);  color:var(--red); }
  .badge.verde { background:rgba(63,185,80,.15);  color:var(--green); }
  form.inline { display:inline; }
  button, input[type=submit] {
    background:var(--accent); color:#fff; border:none; padding:6px 14px;
    border-radius:6px; cursor:pointer; font-size:13px; }
  button:hover { opacity:.85; }
  .alta { background:var(--panel); border:1px solid var(--border);
          border-radius:10px; padding:16px; margin-bottom:22px; }
  .alta input[type=text], .alta input[type=password] {
          background:var(--bg); border:1px solid var(--border);
          color:var(--txt); padding:7px 10px; border-radius:6px; margin-right:8px; }
  .flash { background:rgba(63,185,80,.12); border:1px solid var(--green);
           color:var(--green); padding:9px 14px; border-radius:8px;
           margin-bottom:16px; }
  .vacio { color:var(--dim); padding:24px; text-align:center; }
  .tabs { display:flex; gap:6px; margin-bottom:18px; }
  .tabs button { background:var(--panel); color:var(--dim);
                 border:1px solid var(--border); padding:8px 18px;
                 border-radius:8px 8px 0 0; }
  .tabs button.activa { background:var(--accent); color:#fff;
                        border-color:var(--accent); }
  footer { text-align:center; color:var(--dim); font-size:12px; margin:30px 0; }
</style>
</head>
<body>
<header>
  <h1>🐍 Ouroboros <span>IDS</span></h1>
  <nav>
    {% for ep, nombre in [('resumen','Resumen'), ('dispositivos','Dispositivos'),
                          ('alertas','Alertas Whitelist'), ('dns','Bitácora DNS'),
                          ('blacklist','IPs Peligrosas'), ('usuarios','Usuarios'),
                          ('config','Configuración')] %}
      <a href="{{ url_for(ep) }}" class="{{ 'activa' if vista==ep }}">{{ nombre }}</a>
    {% endfor %}
    <a href="{{ url_for('cambiar_password') }}">Contraseña 🔑</a>
    <a href="{{ url_for('logout') }}" class="salir">Salir ⏻</a>
  </nav>
</header>
<main>
  {% with msgs = get_flashed_messages() %}
    {% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}
  {% endwith %}
  {{ contenido|safe }}
</main>
<footer>Ouroboros IDS — Dashboard de administración · sesión JWT ({{ TOKEN_MIN }} min) · auto-refresh inteligente (se pausa mientras escribes)</footer>
<script>
  // Auto-refresh inteligente: recarga cada 15 s SOLO si el usuario no está
  // escribiendo y ningún campo tiene contenido — así los formularios
  // (como el cambio de contraseña) nunca se borran a media captura.
  setInterval(function () {
    var a = document.activeElement;
    var escribiendo = a && ['INPUT', 'SELECT', 'TEXTAREA'].indexOf(a.tagName) !== -1;
    var camposConTexto = Array.prototype.some.call(
      document.querySelectorAll('input[type=text], input[type=password]'),
      function (i) { return i.value.length > 0; }
    );
    if (!escribiendo && !camposConTexto) location.reload();
  }, 15000);
</script>
</body>
</html>
"""

LOGIN = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Ouroboros IDS — Iniciar sesión</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --txt:#e6edf3;
          --dim:#8b949e; --red:#f85149; --accent:#7c3aed; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--txt); height:100vh;
         display:flex; align-items:center; justify-content:center;
         font:14px/1.5 'Segoe UI', system-ui, sans-serif; }
  .caja { background:var(--panel); border:1px solid var(--border);
          border-radius:12px; padding:34px; width:340px; text-align:center; }
  h1 { font-size:22px; margin-bottom:4px; }
  h1 span { color:var(--accent); }
  p.sub { color:var(--dim); font-size:13px; margin-bottom:22px; }
  input { width:100%; background:var(--bg); border:1px solid var(--border);
          color:var(--txt); padding:10px 12px; border-radius:8px;
          margin-bottom:12px; font-size:14px; }
  button { width:100%; background:var(--accent); color:#fff; border:none;
           padding:10px; border-radius:8px; font-size:14px; cursor:pointer; }
  button:hover { opacity:.88; }
  .error { background:rgba(248,81,73,.12); border:1px solid var(--red);
           color:var(--red); padding:8px; border-radius:8px;
           margin-bottom:14px; font-size:13px; }
  footer { color:var(--dim); font-size:11px; margin-top:18px; }
</style>
</head>
<body>
  <div class="caja">
    <h1>🐍 Ouroboros <span>IDS</span></h1>
    <p class="sub">Identifícate para administrar el sistema</p>
    {% with msgs = get_flashed_messages() %}
      {% for m in msgs %}<div class="error">{{ m }}</div>{% endfor %}
    {% endwith %}
    <form method="post">
      <input type="text" name="usuario" placeholder="Usuario" required autofocus>
      <input type="password" name="clave" placeholder="Contraseña" required>
      <button type="submit">Iniciar sesión</button>
    </form>
    <footer>Acceso autenticado con JWT · expira en {{ TOKEN_MIN }} min</footer>
  </div>
</body>
</html>
"""


def render(vista, titulo, contenido):
    return render_template_string(BASE, vista=vista, titulo=titulo,
                                  contenido=contenido, TOKEN_MIN=TOKEN_MINUTOS)


def tabla(filas, columnas, formato=None):
    """Genera una tabla HTML a partir de filas (lista de dicts)."""
    if not filas:
        return '<div class="vacio">Sin registros todavía — corre seed_demo.py para datos de prueba.</div>'
    formato = formato or {}
    ths = "".join(f"<th>{t}</th>" for _, t in columnas)
    trs = ""
    for f in filas:
        tds = ""
        for campo, _ in columnas:
            val = f.get(campo, "")
            if campo in formato:
                val = formato[campo](f)
            tds += f"<td>{val}</td>"
        trs += f"<tr>{tds}</tr>"
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"


def fecha(iso):
    """Acorta el timestamp ISO para mostrarlo."""
    return (iso or "")[:19].replace("T", " ")


# ── Login / Logout ───────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form["usuario"].strip()
        clave   = request.form["clave"].strip()

        # Identificación + Autenticación contra la tabla usuarios (hash PBKDF2)
        u = buscar_usuario(usuario)
        if u and check_password_hash(u["password_hash"], clave):
            debe_cambiar = bool(u["cambiar_pwd"])
            destino = "cambiar_password" if debe_cambiar else "resumen"
            resp = make_response(redirect(url_for(destino)))
            resp.set_cookie(
                "token", crear_token(u["usuario"], u["rol"], debe_cambiar),
                httponly=True,            # JS no puede leer el token
                samesite="Lax",
                max_age=TOKEN_MINUTOS * 60,
            )
            return resp

        flash("Usuario o contraseña incorrectos.")

    return render_template_string(LOGIN, TOKEN_MIN=TOKEN_MINUTOS)


@app.route("/cambiar-password", methods=["GET", "POST"])
@requiere_token
def cambiar_password():
    datos = validar_token()
    usuario = datos["sub"]

    if request.method == "POST":
        actual    = request.form["actual"].strip()
        nueva     = request.form["nueva"].strip()
        confirmar = request.form["confirmar"].strip()

        u = buscar_usuario(usuario)
        if not check_password_hash(u["password_hash"], actual):
            flash("La contraseña actual es incorrecta.")
        elif len(nueva) < 8:
            flash("La nueva contraseña debe tener al menos 8 caracteres.")
        elif nueva == actual:
            flash("La nueva contraseña debe ser diferente a la actual.")
        elif nueva != confirmar:
            flash("La confirmación no coincide.")
        else:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE usuarios SET password_hash = ?, cambiar_pwd = 0 WHERE usuario = ?",
                    (generate_password_hash(nueva), usuario)
                )
                conn.commit()
            # Re-emitir token sin la marca de contraseña temporal
            resp = make_response(redirect(url_for("resumen")))
            resp.set_cookie(
                "token", crear_token(usuario, datos["rol"], False),
                httponly=True, samesite="Lax", max_age=TOKEN_MINUTOS * 60,
            )
            flash("Contraseña actualizada correctamente.")
            return resp

    obligado = datos.get("pwd") == 1
    aviso = ("""<div class="flash" style="border-color:var(--yellow);
             color:var(--yellow); background:rgba(210,153,34,.12)">
             Tu contraseña es temporal — debes cambiarla para continuar.</div>"""
             if obligado else "")

    contenido = f"""
    {aviso}
    <div class="alta" style="max-width:430px">
      <h2>Cambiar contraseña — {usuario}</h2>
      <form method="post">
        <input type="password" name="actual" placeholder="Contraseña actual"
               required style="width:100%; margin-bottom:10px">
        <input type="password" name="nueva" placeholder="Nueva contraseña (mín. 8 caracteres)"
               required minlength="8" style="width:100%; margin-bottom:10px">
        <input type="password" name="confirmar" placeholder="Confirmar nueva contraseña"
               required minlength="8" style="width:100%; margin-bottom:12px">
        <input type="submit" value="Cambiar contraseña">
      </form>
    </div>"""
    return render("config", "Cambiar contraseña", contenido)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("token")
    return resp


# ── Vistas (todas protegidas con JWT) ────────────────────────────────────────

@app.route("/")
@requiere_token
def resumen():
    total_disp   = scalar("SELECT COUNT(*) FROM dispositivos_conocidos")
    autorizados  = scalar("SELECT COUNT(*) FROM dispositivos_conocidos WHERE autorizado=1")
    alertas_wl   = scalar("SELECT COUNT(*) FROM alertas_whitelist")
    alertas_bl   = scalar("SELECT COUNT(*) FROM alertas_blacklist")
    dns_total    = scalar("SELECT COUNT(*) FROM bitacora_dns")

    top = query("""SELECT dominio, COUNT(*) c FROM bitacora_dns
                   GROUP BY dominio ORDER BY c DESC LIMIT 5""")
    ultimas = query("""SELECT timestamp, ip_origen, ip_peligrosa
                       FROM alertas_blacklist ORDER BY timestamp DESC LIMIT 5""")

    cards = f"""
    <div class="cards">
      <div class="card"><div class="num">{total_disp}</div><div class="lbl">Dispositivos detectados</div></div>
      <div class="card"><div class="num ok">{autorizados}</div><div class="lbl">Autorizados</div></div>
      <div class="card"><div class="num warn">{alertas_wl}</div><div class="lbl">Alertas whitelist</div></div>
      <div class="card"><div class="num mal">{alertas_bl}</div><div class="lbl">Alertas IP peligrosa</div></div>
      <div class="card"><div class="num">{dns_total}</div><div class="lbl">Consultas DNS</div></div>
    </div>"""

    t1 = tabla(top, [("dominio", "Dominio"), ("c", "Visitas")])
    t2 = tabla(ultimas,
               [("timestamp", "Fecha"), ("ip_origen", "IP origen"),
                ("ip_peligrosa", "IP peligrosa")],
               {"timestamp": lambda f: fecha(f["timestamp"])})

    return render("resumen", "Resumen",
                  cards + "<h2>Top dominios visitados</h2>" + t1 +
                  "<h2 style='margin-top:24px'>Últimas alertas de emergencia</h2>" + t2)


@app.route("/dispositivos")
@requiere_token
def dispositivos():
    filas = query("SELECT * FROM dispositivos_conocidos ORDER BY ultimo_visto DESC")

    def estado(f):
        if f["autorizado"]:
            return '<span class="badge verde">Autorizado</span>'
        boton = f"""<form class="inline" method="post"
                     action="{url_for('autorizar', mac=f['mac'])}">
                     <button type="submit">Autorizar</button></form>"""
        return f'<span class="badge rojo">No autorizado</span> {boton}'

    alta = f"""
    <div class="alta">
      <h2>Alta manual en lista blanca (por MAC)</h2>
      <form method="post" action="{url_for('alta_whitelist')}">
        <input type="text" name="mac" placeholder="MAC (AA:BB:CC:DD:EE:FF)" required>
        <input type="submit" value="Autorizar MAC">
      </form>
    </div>"""

    t = tabla(filas,
              [("ip", "IP"), ("mac", "MAC"),
               ("primera_vez_visto", "Primera vez visto"),
               ("ultimo_visto", "Último visto"), ("autorizado", "Estado")],
              {"primera_vez_visto": lambda f: fecha(f["primera_vez_visto"]),
               "ultimo_visto": lambda f: fecha(f["ultimo_visto"]),
               "autorizado": estado})

    return render("dispositivos", "Dispositivos", alta + "<h2>Dispositivos detectados en la red</h2>" + t)


@app.route("/autorizar/<mac>", methods=["POST"])
@requiere_token
def autorizar(mac):
    db_writer.autorizar_dispositivo(mac)
    flash(f"Dispositivo {mac} autorizado.")
    return redirect(url_for("dispositivos"))


@app.route("/alta", methods=["POST"])
@requiere_token
def alta_whitelist():
    mac = request.form["mac"].strip().upper()

    if not re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        flash(f"'{mac}' no es una MAC válida (formato AA:BB:CC:DD:EE:FF).")
        return redirect(url_for("dispositivos"))

    # Directo a la BD — la misma que consulta es_autorizado() del sniffer.
    # IP placeholder: el sniffer la actualiza al ver tráfico de esa MAC.
    db_writer.registrar_y_autorizar("0.0.0.0", mac)
    flash(f"MAC {mac} autorizada en la lista blanca.")
    return redirect(url_for("dispositivos"))


@app.route("/alertas")
@requiere_token
def alertas():
    filas = query("SELECT * FROM alertas_whitelist ORDER BY timestamp DESC LIMIT 200")
    t = tabla(filas,
              [("timestamp", "Fecha"), ("ip", "IP"), ("mac", "MAC"),
               ("detalle", "Detalle"), ("procesada", "Correo enviado")],
              {"timestamp": lambda f: fecha(f["timestamp"]),
               "procesada": lambda f: '<span class="ok">Sí</span>' if f["procesada"]
                                       else '<span class="warn">Pendiente</span>'})
    return render("alertas", "Alertas Whitelist",
                  "<h2>Dispositivos no autorizados detectados (Capa 2/3)</h2>" + t)


@app.route("/dns")
@requiere_token
def dns():
    filtro = request.args.get("ip", "").strip()
    if filtro:
        filas = query("""SELECT ip_origen, dominio, MAX(timestamp) AS timestamp
                         FROM bitacora_dns WHERE ip_origen = ?
                         GROUP BY ip_origen, dominio
                         ORDER BY timestamp DESC LIMIT 300""", (filtro,))
    else:
        filas = query("""SELECT ip_origen, dominio, MAX(timestamp) AS timestamp
                         FROM bitacora_dns
                         GROUP BY ip_origen, dominio
                         ORDER BY timestamp DESC LIMIT 300""")

    buscador = f"""
    <div class="alta">
      <form method="get">
        <input type="text" name="ip" value="{html.escape(filtro)}" placeholder="Filtrar por IP origen">
        <input type="submit" value="Filtrar">
      </form>
    </div>"""

    t = tabla(filas,
              [("timestamp", "Fecha"), ("ip_origen", "IP origen"), ("dominio", "Dominio")],
              {"timestamp": lambda f: fecha(f["timestamp"])})
    return render("dns", "Bitácora DNS",
                  buscador + "<h2>Bitácora de dominios visitados</h2>" + t)


@app.route("/blacklist")
@requiere_token
def blacklist():
    # ── Lista local (editable) — los feeds remotos los descarga el sniffer ──
    ips_lista = sorted(_cargar_blacklist_local())
    filas_txt = [{"ip": ip} for ip in ips_lista]

    def quitar_btn(f):
        return f"""<form class="inline" method="post"
                    action="{url_for('blacklist_quitar')}">
                    <input type="hidden" name="ip" value="{f['ip']}">
                    <button type="submit">Quitar</button></form>"""

    gestion = f"""
    <div class="alta">
      <h2>Agregar IP a la lista negra local</h2>
      <form method="post" action="{url_for('blacklist_agregar')}">
        <input type="text" name="ip" placeholder="IP (ej. 91.92.109.196)" required>
        <input type="submit" value="Agregar">
      </form>
      <p style="color:var(--dim); font-size:12px; margin-top:10px">
        La blacklist efectiva = feeds remotos + esta lista local.
        Los cambios se aplican en caliente — el sniffer recarga en ~5 s.</p>
    </div>"""

    t_txt = tabla(filas_txt, [("ip", "IP en blacklist.txt"), ("acc", "Acción")],
                  {"acc": quitar_btn})

    # ── Fuentes de feeds remotos (tabla feed_sources) ──
    feeds = query("SELECT * FROM feed_sources ORDER BY id")

    def estado_feed(f):
        etiqueta = ('<span class="badge verde">Activo</span>' if f["activo"]
                    else '<span class="badge rojo">Inactivo</span>')
        accion = "Desactivar" if f["activo"] else "Activar"
        boton = f"""<form class="inline" method="post"
                     action="{url_for('feed_toggle', feed_id=f['id'])}">
                     <button type="submit">{accion}</button></form>"""
        return f"{etiqueta} {boton}"

    t_feeds = tabla(feeds,
                    [("nombre", "Feed"), ("url", "URL"),
                     ("ultimo_update", "Última descarga"), ("activo", "Estado")],
                    {"ultimo_update": lambda f: fecha(f["ultimo_update"]) or "—",
                     "activo": estado_feed})

    alta_feed = f"""
    <div class="alta" style="margin-top:14px">
      <h2>Agregar feed de Threat Intelligence</h2>
      <form method="post" action="{url_for('feed_agregar')}">
        <input type="text" name="nombre" placeholder="Nombre (ej. Spamhaus DROP)" required>
        <input type="text" name="url" placeholder="URL del feed (https://...)" required size="40">
        <input type="submit" value="Agregar feed">
      </form>
      <p style="color:var(--dim); font-size:12px; margin-top:10px">
        El feed debe regresar texto plano con una IP por línea
        (líneas con # se ignoran). Se descarga en caliente en ~5 s.</p>
    </div>"""

    # ── Detecciones registradas con análisis forense ──
    filas = query("""
        SELECT a.timestamp, a.ip_origen, a.ip_peligrosa,
               COALESCE(f.tipo_riesgo,  '—') AS tipo_riesgo,
               COALESCE(f.score_abuso,  '—') AS score_abuso,
               COALESCE(f.pais,         '—') AS pais,
               COALESCE(f.isp,          '—') AS isp,
               COALESCE(f.correo_abuso, '—') AS correo_abuso
        FROM alertas_blacklist a
        LEFT JOIN analisis_forense f ON a.ip_peligrosa = f.ip
        ORDER BY a.timestamp DESC LIMIT 200
    """)
    t = tabla(filas,
              [("timestamp", "Fecha"), ("ip_origen", "IP origen"),
               ("ip_peligrosa", "IP peligrosa"), ("tipo_riesgo", "Riesgo"),
               ("score_abuso", "Score"), ("pais", "País"),
               ("isp", "ISP"), ("correo_abuso", "Contacto abuso")],
              {"timestamp": lambda f: fecha(f["timestamp"]),
               "tipo_riesgo": lambda f: (f'<span class="badge rojo">{f["tipo_riesgo"]}</span>'
                                         if f["tipo_riesgo"] != "—" else "—"),
               "score_abuso": lambda f: (f'<span class="mal">{f["score_abuso"]}</span>'
                                         if f["score_abuso"] != "—" else "—")})

    # ── Pestañas: Lista local | Feeds remotos ──
    recarga_pendiente = RELOAD_FLAG.exists()
    aviso_recarga = ("""<div class="flash" style="border-color:var(--yellow);
                     color:var(--yellow); background:rgba(210,153,34,.12)">
                     Hay cambios pendientes — el sniffer los aplicará en ~5 s
                     (si Ouroboros está corriendo).</div>"""
                     if recarga_pendiente else "")

    boton_recarga = f"""
    <form class="inline" method="post" action="{url_for('feeds_actualizar')}"
          style="margin-left:auto">
      <button type="submit">⟳ Actualizar feeds ahora</button>
    </form>"""

    tabs = f"""
    {aviso_recarga}
    <div class="tabs" style="display:flex; align-items:center">
      <button type="button" id="btn-local" class="activa"
              onclick="verTab('local')">Lista local ({len(ips_lista)})</button>
      <button type="button" id="btn-feeds"
              onclick="verTab('feeds')">Feeds remotos ({len(feeds)})</button>
      {boton_recarga}
    </div>

    <div id="tab-local">
      {gestion}
      <h2>Lista negra local ({len(ips_lista)} IPs)</h2>
      {t_txt}
    </div>

    <div id="tab-feeds" style="display:none">
      <h2>Feeds remotos de Threat Intelligence</h2>
      {t_feeds}
      {alta_feed}
    </div>

    <script>
      function verTab(n) {{
        document.getElementById('tab-local').style.display = (n==='local') ? '' : 'none';
        document.getElementById('tab-feeds').style.display = (n==='feeds') ? '' : 'none';
        document.getElementById('btn-local').classList.toggle('activa', n==='local');
        document.getElementById('btn-feeds').classList.toggle('activa', n==='feeds');
        location.hash = n;   // sobrevive al auto-refresh de la página
      }}
      if (location.hash === '#feeds') verTab('feeds');
    </script>"""

    return render("blacklist", "IPs Peligrosas",
                  tabs +
                  "<h2 style='margin-top:24px'>Conexiones a IPs peligrosas — datos forenses (Whois/AbuseIPDB)</h2>" + t)


@app.route("/blacklist/agregar", methods=["POST"])
@requiere_token
def blacklist_agregar():
    import ipaddress
    ip = request.form["ip"].strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        flash(f"'{ip}' no es una IP válida.")
        return redirect(url_for("blacklist"))

    if agregar_ip_local(ip):
        señalar_recarga()
        flash(f"IP {ip} agregada a la lista negra local — el sniffer la aplicará en ~5 s.")
    else:
        flash(f"La IP {ip} ya estaba en la lista negra local.")
    return redirect(url_for("blacklist"))


@app.route("/blacklist/quitar", methods=["POST"])
@requiere_token
def blacklist_quitar():
    ip = request.form["ip"].strip()
    if quitar_ip_local(ip):
        señalar_recarga()
        flash(f"IP {ip} eliminada de la lista negra local — el sniffer lo aplicará en ~5 s.")
    else:
        flash(f"La IP {ip} no estaba en la lista local.")
    return redirect(url_for("blacklist"))


@app.route("/feeds/toggle/<int:feed_id>", methods=["POST"])
@requiere_token
def feed_toggle(feed_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE feed_sources SET activo = 1 - activo WHERE id = ?", (feed_id,)
        )
        conn.commit()
    señalar_recarga()
    flash("Estado del feed actualizado — el sniffer recargará en ~5 s.")
    return redirect(url_for("blacklist") + "#feeds")


@app.route("/feeds/agregar", methods=["POST"])
@requiere_token
def feed_agregar():
    nombre = request.form["nombre"].strip()
    url    = request.form["url"].strip()

    if not url.startswith(("http://", "https://")):
        flash("La URL del feed debe empezar con http:// o https://")
        return redirect(url_for("blacklist"))

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO feed_sources (nombre, url, activo) VALUES (?, ?, 1)",
                (nombre, url)
            )
            conn.commit()
        señalar_recarga()
        flash(f"Feed '{nombre}' agregado — el sniffer lo descargará en ~5 s.")
    except sqlite3.IntegrityError:
        flash(f"Esa URL ya está registrada como feed.")  # url UNIQUE en la tabla
    return redirect(url_for("blacklist") + "#feeds")


@app.route("/feeds/actualizar", methods=["POST"])
@requiere_token
def feeds_actualizar():
    """Fuerza la recarga de feeds + lista local en el sniffer, sin reiniciar."""
    señalar_recarga()
    flash("Recarga solicitada — el sniffer descargará los feeds en ~5 s "
          "(si Ouroboros está corriendo).")
    return redirect(url_for("blacklist") + "#feeds")


# ── Gestión de usuarios (solo rol admin) ─────────────────────────────────────

@app.route("/usuarios")
@requiere_admin
def usuarios():
    sesion = validar_token()
    filas = query("SELECT id, usuario, rol, cambiar_pwd, creado FROM usuarios ORDER BY id")

    def acciones(f):
        if f["usuario"] == sesion["sub"]:
            return '<span class="badge verde">Tu sesión</span>'
        return f"""<form class="inline" method="post"
                    action="{url_for('usuario_eliminar', user_id=f['id'])}"
                    onsubmit="return confirm('¿Eliminar a {f['usuario']}?')">
                    <button type="submit">Eliminar</button></form>"""

    alta = f"""
    <div class="alta">
      <h2>Crear cuenta nueva</h2>
      <form method="post" action="{url_for('usuario_agregar')}">
        <input type="text" name="usuario" placeholder="Usuario" required>
        <input type="password" name="clave" placeholder="Contraseña temporal (mín. 8)"
               required minlength="8">
        <select name="rol" style="background:var(--bg); color:var(--txt);
                border:1px solid var(--border); padding:7px 10px;
                border-radius:6px; margin-right:8px">
          <option value="operador">operador</option>
          <option value="admin">admin</option>
        </select>
        <input type="submit" value="Crear cuenta">
      </form>
      <p style="color:var(--dim); font-size:12px; margin-top:10px">
        La cuenta nueva entra con contraseña temporal y el sistema le
        exigirá cambiarla en su primer login. Rol operador: opera el IDS ·
        Rol admin: además gestiona cuentas y el correo de alertas.</p>
    </div>"""

    t = tabla(filas,
              [("usuario", "Usuario"), ("rol", "Rol"),
               ("cambiar_pwd", "Contraseña"), ("creado", "Creado"), ("acc", "Acción")],
              {"rol": lambda f: (f'<span class="badge verde">{f["rol"]}</span>'
                                 if f["rol"] == "admin"
                                 else f'<span class="badge rojo" style="background:rgba(88,166,255,.15); color:var(--blue)">{f["rol"]}</span>'),
               "cambiar_pwd": lambda f: ('<span class="warn">Temporal</span>'
                                         if f["cambiar_pwd"] else '<span class="ok">Propia</span>'),
               "creado": lambda f: fecha(f["creado"]),
               "acc": acciones})

    return render("usuarios", "Usuarios", alta + "<h2>Cuentas del dashboard</h2>" + t)


@app.route("/usuarios/agregar", methods=["POST"])
@requiere_admin
def usuario_agregar():
    usuario = request.form["usuario"].strip()
    clave   = request.form["clave"].strip()
    rol     = request.form.get("rol", "operador").strip()

    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,30}", usuario):
        flash("Usuario inválido — usa 3-30 caracteres alfanuméricos.")
        return redirect(url_for("usuarios"))
    if len(clave) < 8:
        flash("La contraseña temporal debe tener al menos 8 caracteres.")
        return redirect(url_for("usuarios"))
    if rol not in ROLES_VALIDOS:
        rol = "operador"

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """INSERT INTO usuarios (usuario, password_hash, rol, cambiar_pwd, creado)
                   VALUES (?, ?, ?, 1, ?)""",
                (usuario, generate_password_hash(clave), rol,
                 datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
        flash(f"Cuenta '{usuario}' ({rol}) creada — deberá cambiar su contraseña al entrar.")
    except sqlite3.IntegrityError:
        flash(f"El usuario '{usuario}' ya existe.")
    return redirect(url_for("usuarios"))


@app.route("/usuarios/eliminar/<int:user_id>", methods=["POST"])
@requiere_admin
def usuario_eliminar(user_id):
    sesion = validar_token()
    u = query("SELECT usuario, rol FROM usuarios WHERE id = ?", (user_id,))
    if not u:
        flash("Esa cuenta no existe.")
        return redirect(url_for("usuarios"))
    if u[0]["usuario"] == sesion["sub"]:
        flash("No puedes eliminar tu propia sesión.")
        return redirect(url_for("usuarios"))
    if u[0]["rol"] == "admin":
        admins = scalar("SELECT COUNT(*) FROM usuarios WHERE rol = 'admin'")
        if admins <= 1:
            flash("No se puede eliminar el último administrador.")
            return redirect(url_for("usuarios"))

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
        conn.commit()
    flash(f"Cuenta '{u[0]['usuario']}' eliminada.")
    return redirect(url_for("usuarios"))


# ── Configuración: correo del admin que recibe las alertas ───────────────────

@app.route("/config")
@requiere_admin
def config():
    actual = leer_env_var("ADMIN_EMAIL") or "(no configurado)"
    sesion = validar_token()
    contenido = f"""
    <div class="alta">
      <h2>Correo del administrador (recibe las alertas)</h2>
      <p style="color:var(--dim); margin-bottom:12px">
        Actual: <strong>{actual}</strong> ·
        Sesión: <strong>{sesion['sub']}</strong> (rol {sesion['rol']})</p>
      <form method="post" action="{url_for('cambiar_admin')}">
        <input type="text" name="nuevo_correo" placeholder="Nuevo correo admin" required>
        <input type="submit" value="Cambiar correo">
      </form>
      <p style="color:var(--dim); font-size:12px; margin-top:10px">
        El cambio aplica de inmediato.</p>
    </div>"""
    return render("config", "Configuración", contenido)


@app.route("/config/admin", methods=["POST"])
@requiere_admin
def cambiar_admin():
    nuevo = request.form["nuevo_correo"].strip()

    if "@" not in nuevo or "." not in nuevo.split("@")[-1]:
        flash("Correo inválido.")
        return redirect(url_for("config"))

    escribir_env_var("ADMIN_EMAIL", nuevo)
    flash(f"Correo del administrador actualizado a {nuevo}.")
    return redirect(url_for("config"))


if __name__ == "__main__":
    db_writer.init_db()   # crea tablas si no existen — funciona sin el sniffer
    init_usuarios()       # tabla de cuentas + admin inicial del .env

    # 0.0.0.0 = accesible desde otros dispositivos de la red local
    # vía http://IP-del-servidor:5000 (asegúrate de abrir el puerto en el firewall)
    print("[Ouroboros] Dashboard en http://0.0.0.0:5000 — accesible en la red local")
    app.run(host="0.0.0.0", port=5000, debug=False)
