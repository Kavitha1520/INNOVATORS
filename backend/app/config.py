import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR.parent / ".env")
DB_PATH = BASE_DIR / "db" / "brandshield.db"
UPLOADS_DIR = BASE_DIR / "db" / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

APP_TITLE = "BRANDSHIELD AI"
MYSQL = "unused"

DEBUG = os.getenv("APP_ENV", "development") == "development"
PORT = int(os.getenv("PORT", "8000"))
