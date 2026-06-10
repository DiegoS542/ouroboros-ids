"""
dashboard.py
Ouroboros IDS — Dashboard web de administración
Interfaz Flask para consultar las vistas de la base de datos y
gestionar la lista blanca sin tocar archivos manualmente.

Vistas:
    /             Resumen general (contadores y últimas alertas)
    /dispositivos Dispositivos detectados + autorizar/alta en whitelist
    /alertas      Alertas de dispositivos no autorizados (Capa 2/3)
    /dns          Bitácora de dominios visitados
    /blacklist    Lista negra + conexiones a IPs peligrosas (forense)
    /config       Cambio del correo admin (identificación/autenticación/autorización)

Uso:
    python dashboard.py
    Abrir http://127.0.0.1:5000 en el navegador.

Funciona aunque el sniffer NO esté corriendo: solo lee la base SQLite.
Para probar con datos falsos:  python seed_demo.py
"""

import os
import sqlite3
from flask import Flask, render_template_string, request, redirect, url_for, flash

from config.settings import DB_PATH, BASE_DIR
from core import db_writer, whitelist, blacklist as bl

ENV_PATH = BASE_DIR / ".env"

app = Flask(__name__)
app.secret_key = "ouroboros-dashboard"  # solo para mensajes flash locales


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


# ── Plantilla base ───────────────────────────────────────────────────────────

BASE = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Ouroboros IDS — {{ titulo }}</title>
<meta http-equiv="refresh" content="15">
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
  footer { text-align:center; color:var(--dim); font-size:12px; margin:30px 0; }
</style>
</head>
<body>
<header>
  <h1>🐍 Ouroboros <span>IDS</span></h1>
  <nav>
    {% for ep, nombre in [('resumen','Resumen'), ('dispositivos','Dispositivos'),
                          ('alertas','Alertas Whitelist'), ('dns','Bitácora DNS'),
                          ('blacklist','IPs Peligrosas'), ('config','Configuración')] %}
      <a href="{{ url_for(ep) }}" class="{{ 'activa' if vista==ep }}">{{ nombre }}</a>
    {% endfor %}
  </nav>
</header>
<main>
  {% with msgs = get_flashed_messages() %}
    {% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}
  {% endwith %}
  {{ contenido|safe }}
</main>
<footer>Ouroboros IDS — Dashboard de administración · auto-refresh cada 15 s</footer>
</body>
</html>
"""


def render(vista, titulo, contenido):
    return render_template_string(BASE, vista=vista, titulo=titulo, contenido=contenido)


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


# ── Vistas ───────────────────────────────────────────────────────────────────

@app.route("/")
def resumen():
    total_disp   = scalar("SELECT COUNT(*) FROM dispositivos_conocidos")
    autorizados  = scalar("SELECT COUNT(*) FROM dispositivos_conocidos WHERE autorizado=1")
    alertas_wl   = scalar("SELECT COUNT(*) FROM alertas_whitelist")
    alertas_bl   = scalar("SELECT COUNT(*) FROM alertas_blacklist")
    dns_total    = scalar("SELECT COUNT(*) FROM bitacora_dns")

    top = query("""SELECT dominio, COUNT(*) c FROM bitacora_dns
                   GROUP BY dominio ORDER BY c DESC LIMIT 5""")
    ultimas = query("""SELECT timestamp, ip_peligrosa, tipo_riesgo, score_abuso
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
               [("timestamp", "Fecha"), ("ip_peligrosa", "IP peligrosa"),
                ("tipo_riesgo", "Riesgo"), ("score_abuso", "Score")],
               {"timestamp": lambda f: fecha(f["timestamp"]),
                "tipo_riesgo": lambda f: f'<span class="badge rojo">{f["tipo_riesgo"]}</span>'})

    return render("resumen", "Resumen",
                  cards + "<h2>Top dominios visitados</h2>" + t1 +
                  "<h2 style='margin-top:24px'>Últimas alertas de emergencia</h2>" + t2)


@app.route("/dispositivos")
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
      <h2>Alta manual en lista blanca</h2>
      <form method="post" action="{url_for('alta_whitelist')}">
        <input type="text" name="nombre" placeholder="Nombre (ej. PC Sergio)" required>
        <input type="text" name="ip"  placeholder="IP (192.168.1.x)" required>
        <input type="text" name="mac" placeholder="MAC (AA:BB:CC:DD:EE:FF)" required>
        <input type="submit" value="Agregar">
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
def autorizar(mac):
    db_writer.autorizar_dispositivo(mac)
    flash(f"Dispositivo {mac} autorizado.")
    return redirect(url_for("dispositivos"))


@app.route("/alta", methods=["POST"])
def alta_whitelist():
    nombre = request.form["nombre"].strip()
    ip     = request.form["ip"].strip()
    mac    = request.form["mac"].strip().upper()

    whitelist.agregar_dispositivo(nombre, ip, mac)   # whitelist.json
    db_writer.registrar_y_autorizar(ip, mac)          # base de datos
    flash(f"'{nombre}' agregado a la lista blanca ({ip} / {mac}).")
    return redirect(url_for("dispositivos"))


@app.route("/alertas")
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
def dns():
    filtro = request.args.get("ip", "").strip()
    if filtro:
        filas = query("""SELECT * FROM bitacora_dns WHERE ip_origen = ?
                         ORDER BY timestamp DESC LIMIT 300""", (filtro,))
    else:
        filas = query("SELECT * FROM bitacora_dns ORDER BY timestamp DESC LIMIT 300")

    buscador = f"""
    <div class="alta">
      <form method="get">
        <input type="text" name="ip" value="{filtro}" placeholder="Filtrar por IP origen">
        <input type="submit" value="Filtrar">
      </form>
    </div>"""

    t = tabla(filas,
              [("timestamp", "Fecha"), ("ip_origen", "IP origen"), ("dominio", "Dominio")],
              {"timestamp": lambda f: fecha(f["timestamp"])})
    return render("dns", "Bitácora DNS",
                  buscador + "<h2>Bitácora de dominios visitados</h2>" + t)


@app.route("/blacklist")
def blacklist():
    # ── Gestión de blacklist.txt ──
    ips_lista = sorted(bl.cargar_blacklist())
    filas_txt = [{"ip": ip} for ip in ips_lista]

    def quitar_btn(f):
        return f"""<form class="inline" method="post"
                    action="{url_for('blacklist_quitar')}">
                    <input type="hidden" name="ip" value="{f['ip']}">
                    <button type="submit">Quitar</button></form>"""

    gestion = f"""
    <div class="alta">
      <h2>Agregar IP a la lista negra</h2>
      <form method="post" action="{url_for('blacklist_agregar')}">
        <input type="text" name="ip" placeholder="IP (ej. 91.92.109.196)" required>
        <input type="text" name="comentario" placeholder="Motivo (ej. C2 Server)">
        <input type="submit" value="Agregar">
      </form>
      <p style="color:var(--dim); font-size:12px; margin-top:10px">
        Nota: el sniffer carga la blacklist al arrancar — los cambios
        aplican al reiniciar Ouroboros.</p>
    </div>"""

    t_txt = tabla(filas_txt, [("ip", "IP en blacklist.txt"), ("acc", "Acción")],
                  {"acc": quitar_btn})

    # ── Detecciones registradas ──
    filas = query("SELECT * FROM alertas_blacklist ORDER BY timestamp DESC LIMIT 200")
    t = tabla(filas,
              [("timestamp", "Fecha"), ("ip_origen", "IP origen"),
               ("ip_peligrosa", "IP peligrosa"), ("tipo_riesgo", "Riesgo"),
               ("score_abuso", "Score"), ("pais", "País"),
               ("isp", "ISP"), ("correo_abuso", "Contacto abuso")],
              {"timestamp": lambda f: fecha(f["timestamp"]),
               "tipo_riesgo": lambda f: f'<span class="badge rojo">{f["tipo_riesgo"]}</span>',
               "score_abuso": lambda f: f'<span class="mal">{f["score_abuso"]}</span>'})

    return render("blacklist", "IPs Peligrosas",
                  gestion +
                  f"<h2>Lista negra cargada ({len(ips_lista)} IPs)</h2>" + t_txt +
                  "<h2 style='margin-top:24px'>Conexiones a IPs peligrosas — datos forenses (Whois/AbuseIPDB)</h2>" + t)


@app.route("/blacklist/agregar", methods=["POST"])
def blacklist_agregar():
    import ipaddress
    ip = request.form["ip"].strip()
    comentario = request.form.get("comentario", "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        flash(f"'{ip}' no es una IP válida.")
        return redirect(url_for("blacklist"))

    if bl.agregar_ip(ip, comentario):
        flash(f"IP {ip} agregada a la lista negra.")
    else:
        flash(f"La IP {ip} ya estaba en la lista negra.")
    return redirect(url_for("blacklist"))


@app.route("/blacklist/quitar", methods=["POST"])
def blacklist_quitar():
    ip = request.form["ip"].strip()
    if bl.quitar_ip(ip):
        flash(f"IP {ip} eliminada de la lista negra.")
    else:
        flash(f"La IP {ip} no estaba en la lista.")
    return redirect(url_for("blacklist"))


# ── Configuración (correo del admin con Identificación/Autenticación/Autorización) ──

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


@app.route("/config")
def config():
    actual = leer_env_var("ADMIN_EMAIL") or "(no configurado)"
    contenido = f"""
    <div class="alta">
      <h2>Correo del administrador (recibe las alertas)</h2>
      <p style="color:var(--dim); margin-bottom:12px">
        Actual: <strong>{actual}</strong></p>
      <form method="post" action="{url_for('cambiar_admin')}">
        <input type="text" name="usuario" placeholder="Usuario admin" required>
        <input type="password" name="clave" placeholder="Contraseña del dashboard" required>
        <input type="text" name="nuevo_correo" placeholder="Nuevo correo admin" required>
        <input type="submit" value="Cambiar correo">
      </form>
      <p style="color:var(--dim); font-size:12px; margin-top:10px">
        Identificación: usuario · Autenticación: contraseña ·
        Autorización: solo el rol admin puede modificar el destinatario de alertas.
        El cambio aplica de inmediato — el mailer recarga el .env en cada envío.</p>
    </div>"""
    return render("config", "Configuración", contenido)


@app.route("/config/admin", methods=["POST"])
def cambiar_admin():
    usuario = request.form["usuario"].strip()
    clave   = request.form["clave"].strip()
    nuevo   = request.form["nuevo_correo"].strip()

    # Identificación + Autenticación + Autorización contra el .env
    if usuario != leer_env_var("DASHBOARD_USER") or clave != leer_env_var("DASHBOARD_PASSWORD"):
        flash("Acceso denegado: usuario o contraseña incorrectos.")
        return redirect(url_for("config"))

    if "@" not in nuevo or "." not in nuevo.split("@")[-1]:
        flash("Correo inválido.")
        return redirect(url_for("config"))

    escribir_env_var("ADMIN_EMAIL", nuevo)
    flash(f"Correo del administrador actualizado a {nuevo}.")
    return redirect(url_for("config"))


if __name__ == "__main__":
    db_writer.init_db()  # crea tablas si no existen — funciona sin el sniffer
    print("[Ouroboros] Dashboard en http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
