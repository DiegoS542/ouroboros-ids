"""
services/mailer.py
Ouroboros IDS — Módulo de alertas por correo
Responsable: Jaime

Este módulo envía correos de alerta al administrador del sistema.
El correo del administrador se lee desde .env (ADMIN_EMAIL) para
cumplir con el principio de identificación, autenticación y autorización
especificado en la rúbrica — nunca está hardcoded en el código.

Funciones requeridas:
    - enviar_alerta_whitelist()  → dispositivo no autorizado detectado
    - enviar_alerta_blacklist()  → conexión a IP peligrosa detectada
    - enviar_reporte_forense()   → reporte completo con datos de abuso

Dependencias:
    - smtplib   (librería estándar de Python, no requiere instalación)
    - email     (librería estándar de Python, no requiere instalación)
    - config.settings → SMTP_EMAIL, SMTP_PASSWORD, SMTP_HOST, SMTP_PORT, ADMIN_EMAIL
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config.settings import (
    SMTP_EMAIL,
    SMTP_PASSWORD,
    SMTP_HOST,
    SMTP_PORT,
    ADMIN_EMAIL
)


def _conectar_smtp():
    """
    Función interna — establece y retorna una conexión SMTP autenticada.
    Jaime debe implementar esta función primero, las demás la usan.

    Retorna: objeto smtplib.SMTP listo para enviar correos.

    Hint:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        return server
    """
    pass


def enviar_alerta_whitelist(ip, mac, detalle=""):
    """
    Envía un correo al administrador cuando se detecta un dispositivo
    no autorizado en la red (IP o MAC no registrada en whitelist).

    Parámetros:
        ip      — IP del dispositivo no autorizado (str)
        mac     — MAC del dispositivo no autorizado (str)
        detalle — información adicional, ej: "Tráfico hacia 8.8.8.8" (str)

    El correo debe incluir:
        - Asunto:  "[Ouroboros] Alerta — Dispositivo no autorizado"
        - Cuerpo:  IP, MAC, detalle, timestamp
        - Destino: ADMIN_EMAIL (desde settings)

    Retorna: True si el correo se envió, False si hubo error.
    """
    pass


def enviar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa):
    """
    Envía un correo de EMERGENCIA cuando un dispositivo de la red
    se conecta a una IP peligrosa de la blacklist.

    Parámetros:
        ip_origen    — IP del dispositivo en la red local (str)
        mac_origen   — MAC del dispositivo en la red local (str)
        ip_peligrosa — IP externa peligrosa detectada (str)

    El correo debe incluir:
        - Asunto:  "[Ouroboros] 🚨 EMERGENCIA — Conexión a IP peligrosa"
        - Cuerpo:  ip_origen, mac_origen, ip_peligrosa, timestamp
        - Destino: ADMIN_EMAIL (desde settings)

    Retorna: True si el correo se envió, False si hubo error.
    """
    pass


def enviar_reporte_forense(ip_origen, mac_origen, ip_peligrosa,
                            tipo_riesgo, score_abuso, pais,
                            isp, correo_abuso):
    """
    Envía el reporte forense completo al administrador cuando se detecta
    una IP peligrosa. Este correo incluye todos los datos de abuso para
    que el admin pueda reportar directamente al proveedor.

    Parámetros:
        ip_origen    — IP del dispositivo en la red local (str)
        mac_origen   — MAC del dispositivo en la red local (str)
        ip_peligrosa — IP externa peligrosa (str)
        tipo_riesgo  — tipo de amenaza, ej: "Tor Exit Node" (str)
        score_abuso  — score de AbuseIPDB del 0 al 100 (int)
        pais         — país de origen de la IP peligrosa (str)
        isp          — proveedor de internet de la IP peligrosa (str)
        correo_abuso — correo de abuso del proveedor para reportar (str)

    El correo debe incluir:
        - Asunto:  "[Ouroboros] Reporte Forense — {ip_peligrosa}"
        - Cuerpo:  todos los parámetros organizados claramente
        - Pie:     instrucción de cómo reenviar a correo_abuso
        - Destino: ADMIN_EMAIL (desde settings)

    Retorna: True si el correo se envió, False si hubo error.
    """
    pass