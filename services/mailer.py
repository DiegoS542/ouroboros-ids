"""
services/mailer.py
Ouroboros IDS — Módulo de alertas por correo
Responsable: Jaime

Este módulo envía correos de alerta en formato HTML estilizado al administrador.
Soporta recarga dinámica de credenciales si se modifican desde el dashboard.
"""

import smtplib
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
# Importamos los valores iniciales de configuración como fallback
from config.settings import (
    SMTP_HOST,
    SMTP_PORT,
    ADMIN_EMAIL
)

def _conectar_smtp():
    from dotenv import load_dotenv
    import os
    # Agregamos BASE_DIR a la importación
    from config.settings import SMTP_HOST, SMTP_PORT, BASE_DIR
    
    # Le indicamos a load_dotenv la ruta exacta y absoluta del archivo
    ruta_env = BASE_DIR / ".env"
    load_dotenv(dotenv_path=ruta_env, override=True)
    
    # Obtener credenciales actualizadas
    correo_actual = os.getenv("SMTP_EMAIL")
    password_actual = os.getenv("SMTP_PASSWORD")
    host_actual = os.getenv("SMTP_HOST", SMTP_HOST)
    puerto_actual = int(os.getenv("SMTP_PORT", SMTP_PORT))

    if not correo_actual or not password_actual:
        print("[-] Error en Mailer: Faltan credenciales SMTP en el entorno.")
        return None

    try:
        server = smtplib.SMTP(host_actual, puerto_actual)
        server.starttls()
        server.login(correo_actual, password_actual)
        return server
    except Exception as e:
        print(f"[-] Error de conexión SMTP: {e}")
        return None
    
    
def _generar_html_base(titulo, color_banner, contenido_tabla, nota_adicional=""):
    """
    Estructura visual estandarizada en HTML para los correos del IDS.
    """
    return f"""
    <html>
    <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; padding: 20px; margin: 0;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.1); border: 1px solid #e1e8ed;">
            <div style="background-color: {color_banner}; padding: 20px; text-align: center; color: white;">
                <h2 style="margin: 0; font-size: 22px; letter-spacing: 1px;">{titulo}</h2>
                <p style="margin: 5px 0 0 0; opacity: 0.9; font-size: 14px;">Ouroboros Intrusion Detection System</p>
            </div>
            <div style="padding: 25px; color: #2c3e50;">
                <table style="width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 15px;">
                    {contenido_tabla}
                </table>
                {nota_adicional}
            </div>
            <div style="background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 11px; color: #95a5a6; border-top: 1px solid #e1e8ed;">
                Alerta automatizada de seguridad perimetral.<br>
                Infraestructura Institucional &copy; 2026
            </div>
        </div>
    </body>
    </html>
    """


def enviar_alerta_whitelist(ip, mac, detalle=""):
    """
    Recibe los datos del host sospechoso y envía la alerta al administrador.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    asunto = "[Ouroboros] Alerta — Dispositivo no autorizado"
    color_advertencia = "#f39c12" 

    tabla = f"""
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold; width: 35%;">Evento:</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; color: {color_advertencia}; font-weight: bold;">Dispositivo No Autorizado</td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Dirección IP:</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-family: monospace;">{ip}</td>
        </tr>
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Dirección MAC:</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-family: monospace;">{mac}</td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Fecha / Hora:</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed;">{timestamp}</td>
        </tr>
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 10px; font-weight: bold; vertical-align: top;">Detalles:</td>
            <td style="padding: 10px; font-size: 14px; color: #7f8c8d;">{detalle if detalle else 'Sin detalles adicionales.'}</td>
        </tr>
    """

    nota = """
    <div style="margin-top: 25px; background-color: #fef9e7; padding: 12px; border-left: 4px solid #f39c12; border-radius: 4px; font-size: 13px;">
        <strong>Acción requerida:</strong> Evalúe si este host requiere autorización en la whitelist mediante el panel de control.
    </div>
    """

    html_content = _generar_html_base("⚠️ DISPOSITIVO NO REGISTRADO", color_advertencia, tabla, nota)
    
    server = _conectar_smtp()
    if not server:
        return False

    try:
        # Volvemos a leer el emisor y administrador del entorno por si cambiaron
        remitente = os.getenv("SMTP_EMAIL")
        destinatario = os.getenv("ADMIN_EMAIL", ADMIN_EMAIL)

        msg = MIMEMultipart()
        msg['From'] = remitente
        msg['To'] = destinatario
        msg['Subject'] = asunto
        msg.attach(MIMEText(html_content, 'html'))

        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[-] Error al mandar correo de whitelist: {e}")
        return False


def enviar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa):
    """
    Envía un correo de emergencia ante conexiones a IPs comprometidas.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    asunto = "[Ouroboros] 🚨 EMERGENCIA — Conexión a IP peligrosa"
    color_peligro = "#e74c3c" 

    tabla = f"""
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold; width: 35%;">Evento:</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; color: {color_peligro}; font-weight: bold;">Conexión Crítica Detectada</td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">IP Local (Origen):</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-family: monospace;">{ip_origen}</td>
        </tr>
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">MAC Local (Origen):</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-family: monospace;">{mac_origen}</td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">IP Externa (Peligrosa):</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-family: monospace; color: {color_peligro}; font-weight: bold;">{ip_peligrosa}</td>
        </tr>
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Fecha / Hora:</td>
            <td style="padding: 10px; border-bottom: 1px solid #e1e8ed;">{timestamp}</td>
        </tr>
    """

    nota = f"""
    <div style="margin-top: 25px; background-color: #fdedec; padding: 12px; border-left: 4px solid #e74c3c; border-radius: 4px; font-size: 13px;">
        <strong>Atención:</strong> Tráfico saliente hacia un destino malicioso. Se iniciará análisis forense de la IP externa.
    </div>
    """

    html_content = _generar_html_base("🚨 ALERTA DE EMERGENCIA", color_peligro, tabla, nota)

    server = _conectar_smtp()
    if not server:
        return False

    try:
        remitente = os.getenv("SMTP_EMAIL")
        destinatario = os.getenv("ADMIN_EMAIL", ADMIN_EMAIL)

        msg = MIMEMultipart()
        msg['From'] = remitente
        msg['To'] = destinatario
        msg['Subject'] = asunto
        msg.attach(MIMEText(html_content, 'html'))

        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[-] Error al mandar correo de blacklist: {e}")
        return False


def enviar_reporte_forense(ip_origen, mac_origen, ip_peligrosa,
                           tipo_riesgo, score_abuso, pais,
                           isp, correo_abuso):
    """
    Envía un informe forense detallado estructurando las consultas de las APIs.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    asunto = f"[Ouroboros] Reporte Forense — {ip_peligrosa}"
    color_forense = "#2c3e50" 

    tabla = f"""
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-weight: bold; width: 40%;">IP Externa Analizada:</td>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-family: monospace; font-weight: bold;">{ip_peligrosa}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Tipo de Amenaza:</td>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; color: #e74c3c; font-weight: bold;">{tipo_riesgo}</td>
        </tr>
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Abuse Score (0-100):</td>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">{score_abuso}%</td>
        </tr>
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">País de Origen:</td>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed;">{pais}</td>
        </tr>
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Proveedor (ISP):</td>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-size: 14px;">{isp}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Contacto de Abuso:</td>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-family: monospace; color: #2980b9;">{correo_abuso if correo_abuso else 'No disponible'}</td>
        </tr>
        <tr style="background-color: #f8f9fa;">
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-weight: bold;">Host Interno Implicado:</td>
            <td style="padding: 8px; border-bottom: 1px solid #e1e8ed; font-family: monospace;">{ip_origen} ({mac_origen})</td>
        </tr>
    """

    nota = f"""
    <div style="margin-top: 25px; background-color: #ebf5fb; padding: 12px; border-left: 4px solid #2980b9; border-radius: 4px; font-size: 13px;">
        <strong>Cumplimiento Forense:</strong> Reenvíe este reporte técnico al contacto del proveedor (<strong>{correo_abuso if correo_abuso else 'N/A'}</strong>) para solicitar la mitigación del host atacante.
    </div>
    """

    html_content = _generar_html_base("📊 REPORTE DE INTELIGENCIA FORENSE", color_forense, tabla, nota)

    server = _conectar_smtp()
    if not server:
        return False

    try:
        remitente = os.getenv("SMTP_EMAIL")
        destinatario = os.getenv("ADMIN_EMAIL", ADMIN_EMAIL)

        msg = MIMEMultipart()
        msg['From'] = remitente
        msg['To'] = destinatario
        msg['Subject'] = asunto
        msg.attach(MIMEText(html_content, 'html'))

        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[-] Error al mandar reporte forense: {e}")
        return False