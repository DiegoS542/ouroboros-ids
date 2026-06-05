"""
config/settings.py
Ouroboros IDS — Módulo de configuración central
Lee variables de entorno desde .env y las expone al resto del proyecto.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Busca el .env en la raíz del proyecto (un nivel arriba de /config)
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# ── Correo ──────────────────────────────────────────────
SMTP_EMAIL    = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
ADMIN_EMAIL   = os.getenv("ADMIN_EMAIL")

# ── APIs externas ────────────────────────────────────────
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

# ── Base de datos ────────────────────────────────────────
DB_PATH = BASE_DIR / os.getenv("DB_PATH", "data/ouroboros.db")

# ── Validación al arrancar ───────────────────────────────
REQUIRED = {
    "SMTP_EMAIL":     SMTP_EMAIL,
    "SMTP_PASSWORD":  SMTP_PASSWORD,
    "ADMIN_EMAIL":    ADMIN_EMAIL,
    "ABUSEIPDB_KEY":  ABUSEIPDB_KEY,
}

def validate():
    missing = [k for k, v in REQUIRED.items() if not v]
    if missing:
        raise EnvironmentError(
            f"[Ouroboros] Faltan variables de entorno: {', '.join(missing)}\n"
            f"Revisa tu archivo .env"
        )
