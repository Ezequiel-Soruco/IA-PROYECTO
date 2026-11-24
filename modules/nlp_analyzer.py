"""
modules/nlp_analyzer.py - Extracción de Entidades (NER), Vectores de Ataque y NLP Boliviano
"""

import re
import joblib
from pathlib import Path
from config import MESSAGE_MODEL_PATH

message_pipeline = None

def load_nlp_model():
    global message_pipeline
    if Path(MESSAGE_MODEL_PATH).exists() and message_pipeline is None:
        try:
            message_pipeline = joblib.load(MESSAGE_MODEL_PATH)
        except Exception:
            pass

load_nlp_model()

BOLIVIAN_ENTITIES_MAP = {
    "banco union": "Banco Unión",
    "bancounion": "Banco Unión",
    "bnb": "Banco Nacional de Bolivia (BNB)",
    "mercantil santa cruz": "Banco Mercantil Santa Cruz (BMSC)",
    "bmsc": "Banco Mercantil Santa Cruz (BMSC)",
    "bisa": "Banco BISA",
    "bancosol": "BancoSol",
    "fie": "Banco FIE",
    "yape": "Yape Bolivia",
    "tigo money": "Tigo Money",
    "tigomoney": "Tigo Money",
    "gamlp": "Gobierno Autónomo Municipal de La Paz (GAMLP)",
    "alcaldia de la paz": "GAMLP",
    "subalcaldia": "Subalcaldía GAMLP",
    "impuestos nacionales": "Servicio de Impuestos Nacionales (SIN)",
    "sin bolivia": "SIN Bolivia",
    "entel": "Entel Bolivia",
    "segip": "SEGIP (Identificación Personal)",
    "delapaz": "DeLaPaz (Electricidad)",
    "aduana": "Aduana Nacional de Bolivia",
    "asfi": "ASFI (Supervisión Financiera)",
    "ruat": "RUAT (Impuesto Vehicular/Inmueble)",
    "umsa": "Universidad Mayor de San Andrés (UMSA)"
}

ATTACK_VECTORS_KEYWORDS = {
    "Robo de Credenciales / Bloqueo": ["bloqueada", "suspendida", "token", "clave", "pin", "contraseña", "desvincular", "actualizar datos", "verifique su identidad"],
    "Falso Bono / Subsidio Social": ["bono", "bono extraordinario", "bono juana azurduy", "renta dignidad", "covid", "subsidio", "cobrar", "premio", "ganaste", "seleccionado"],
    "Falsa Multa / Cobro Judicial": ["multa", "infraccion", "embargo", "deuda pendiente", "corte de servicio", "delapaz", "impuestos", "sancionado"],
    "Estafa de Pago QR / Reversión": ["qr", "comprobante", "pago retenido", "liberar saldo", "transferencia entrante", "yape"],
    "Malware APK / Troyano Bancario": [".apk", "instalar aplicacion", "actualizacion urgente", "descargar app"]
}

def analyze_message_content(text: str) -> dict:
    """
    Analiza un mensaje con el modelo de ML (TF-IDF + LogisticRegression)
    y ejecuta NER para identificar entidad suplantada y vector de ataque.
    """
    if not text or not text.strip():
        return {
            "ml_prob": 0.0,
            "entity_targeted": None,
            "attack_type": "No determinado",
            "detected_triggers": []
        }
        
    text_clean = text.strip()
    text_lower = text_clean.lower()
    
    # 1. Probabilidad ML
    ml_prob = 0.0
    if message_pipeline is not None:
        try:
            ml_prob = float(message_pipeline.predict_proba([text_clean])[0][1])
        except Exception:
            ml_prob = 0.5
            
    # 2. NER de Entidades Bolivianas
    detected_entity = None
    for pattern, official_name in BOLIVIAN_ENTITIES_MAP.items():
        if re.search(r'\b' + re.escape(pattern) + r'\b', text_lower):
            detected_entity = official_name
            break
            
    # 3. Clasificación de Vector de Ataque
    detected_vector = "Ingeniería Social Genérica"
    detected_triggers = []
    
    for vector_name, keywords in ATTACK_VECTORS_KEYWORDS.items():
        found = [k for k in keywords if k in text_lower]
        if found:
            detected_vector = vector_name
            detected_triggers.extend(found)
            
    # 4. Detección de Número de Teléfono Extranjero suplantando Bolivia
    # e.g., +234, +62, +1, +51 fingiendo ser banco boliviano
    foreign_phone = bool(re.search(r'\+(?!(?:591))\d{1,4}[- ]?\d{6,12}', text))
    if foreign_phone:
        detected_triggers.append("Remitente con código internacional extranjero (No +591)")

    return {
        "ml_prob": ml_prob,
        "entity_targeted": detected_entity,
        "attack_type": detected_vector,
        "detected_triggers": list(set(detected_triggers)),
        "foreign_phone_detected": foreign_phone
    }
