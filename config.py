import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Configuración Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

# Base de datos local SQLite (fallback)
SQLITE_DB_PATH = BASE_DIR / "escudo_digital.db"

# Modelos
MODELS_DIR = BASE_DIR / "models"
URL_MODEL_PATH = MODELS_DIR / "url_model.pkl"
MESSAGE_MODEL_PATH = MODELS_DIR / "message_model.pkl"

# Macrodistritos de La Paz
MACRODISTRITOS_LA_PAZ = [
    "Centro (El Prado, UMSA, Casco Urbano)",
    "Max Paredes (Eloy Salmón, Uyustus, Buenos Aires)",
    "Cotahuma (Sopocachi, San Pedro, Pasankeri)",
    "Sur (Calacoto, San Miguel, Obrajes, Achumani)",
    "San Antonio (Villa Copacabana, Pampahasi)",
    "Periférica (Achachicala, Vino Tinto)",
    "Mallasa (Mallasilla, Jupapina)",
    "El Alto / Zona Conurbada (Ceja, Senkata)"
]

# Dominios oficiales de Bolivia
OFFICIAL_BOLIVIAN_DOMAINS = [
    "bancounion.com.bo",
    "bnb.com.bo",
    "bmsc.com.bo",
    "bisa.com.bo",
    "bancosol.com.bo",
    "bancofie.com.bo",
    "lapaz.bo",
    "gamlp.gob.bo",
    "impuestos.gob.bo",
    "entel.bo",
    "tigo.com.bo",
    "viva.com.bo",
    "delapaz.bo",
    "segip.gob.bo",
    "yape.com.bo",
    "tigomoney.com.bo",
    "gob.bo",
    "aduana.gob.bo",
    "ruat.gob.bo",
    "bcb.gob.bo",
    "asfi.gob.bo",
    "umsa.bo"
]
