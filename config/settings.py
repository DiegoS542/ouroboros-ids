import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SMTP_EMAIL    = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
ADMIN_EMAIL   = os.getenv("ADMIN_EMAIL")

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

DB_PATH = BASE_DIR / os.getenv("DB_PATH", "data/ouroboros.db")

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


def get_smtp_credentials():
    load_dotenv(BASE_DIR / ".env", override=True)
    return {
        "email":    os.getenv("SMTP_EMAIL"),
        "password": os.getenv("SMTP_PASSWORD"),
        "host":     os.getenv("SMTP_HOST", "smtp.gmail.com"),
        "port":     int(os.getenv("SMTP_PORT", 587)),
        "admin":    os.getenv("ADMIN_EMAIL"),
    }
