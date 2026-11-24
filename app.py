"""
app.py - Servidor Web FastAPI de Ciberseguridad e IA
Escudo Digital La Paz - Detección Temprana de Phishing, Smishing y Fraude Digital

Endpoints API:
  - GET  /                           -> Dashboard SOC Web
  - POST /api/v1/analyze-url         -> Análisis Léxico + OSINT (WHOIS, SSL, Redirecciones) + ML
  - POST /api/v1/analyze-message     -> Análisis NLP + NER + Vectores de Ataque Bolivianos
  - POST /api/v1/analyze-image       -> OCR de Captura de Pantalla + Análisis Conjunto
  - POST /api/v1/report-incident     -> Registro de amenaza con Macrodistrito de La Paz (Supabase/SQLite)
  - GET  /api/v1/threat-map          -> Estadísticas georreferenciadas y mapa de incidentes en La Paz
  - POST /api/analyze                -> Retrocompatibilidad
  - GET  /api/history                -> Retrocompatibilidad
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from config import MACRODISTRITOS_LA_PAZ
from features import extract_url_features, get_url_risk_factors, get_message_risk_factors
from modules.url_inspector import follow_redirections, inspect_ssl_certificate, inspect_whois_domain
from modules.nlp_analyzer import analyze_message_content
from modules.ocr_reader import extract_text_from_image
from core.risk_engine import calculate_unified_risk
from core.supabase_client import save_threat_report, get_recent_reports, get_la_paz_threat_statistics

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("escudo-digital")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
MODELS_DIR = BASE_DIR / "models"

app = FastAPI(
    title="Escudo Digital La Paz - Ciberseguridad & IA",
    description="Sistema Inteligente de Detección Temprana de Phishing, Smishing y Fraude Digital en La Paz, Bolivia",
    version="2.0.0"
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Cargar modelo ML de URLs
url_model = None
def load_url_model():
    global url_model
    p = MODELS_DIR / "url_model.pkl"
    if p.exists() and url_model is None:
        try:
            import joblib
            url_model = joblib.load(p)
            logger.info("✅ Modelo de URLs cargado")
        except Exception as e:
            logger.warning(f"Error cargando url_model: {e}")

load_url_model()

# ── Modelos Pydantic ──────────────────────────────────────────────
class AnalyzeUrlRequest(BaseModel):
    url: str
    macrodistrito: Optional[str] = "No especificado"

class AnalyzeMessageRequest(BaseModel):
    message: str
    macrodistrito: Optional[str] = "No especificado"

class IncidentReportRequest(BaseModel):
    input_type: str
    target_url: Optional[str] = None
    message_content: Optional[str] = None
    risk_score: float
    verdict: str
    entity_targeted: Optional[str] = "No identificada"
    attack_type: Optional[str] = "General"
    macrodistrito: str
    factors: List[str]

class LegacyAnalyzeRequest(BaseModel):
    url: Optional[str] = None
    message: Optional[str] = None
    macrodistrito: Optional[str] = "No especificado"

# ── Endpoints Principales ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Dashboard SOC Web"""
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/v1/analyze-url")
async def api_analyze_url(req: AnalyzeUrlRequest, request: Request):
    """
    Inspección de Ciberseguridad Profunda de URL:
     - Detección de Typosquatting contra bancos/gobierno boliviano.
     - Entropía de Shannon (DGA).
     - Rastro de Redirecciones HTTP (301/302).
     - Auditoría SSL/TLS.
     - Antigüedad de Dominio WHOIS.
     - Clasificación por RandomForest ML.
    """
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Debe ingresar una URL válida.")
        
    parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    hostname = parsed.hostname or ""
    
    # 1. ML y características léxicas
    ml_prob = 0.0
    if url_model is not None:
        try:
            feats = extract_url_features(url)
            ml_prob = float(url_model.predict_proba([feats])[0][1])
        except Exception:
            ml_prob = 0.5
            
    lexical_factors = get_url_risk_factors(url)
    url_analysis = {
        "analyzed": True,
        "raw_ml_prob": ml_prob,
        "factors": lexical_factors
    }
    
    # 2. Motor OSINT / Infraestructura Técnica
    redirections = follow_redirections(url)
    ssl_info = inspect_ssl_certificate(hostname) if parsed.scheme == "https" or url.startswith("https") else {"has_ssl": False, "error": "Protocolo HTTP sin cifrar"}
    whois_info = inspect_whois_domain(hostname)
    
    infra_analysis = {
        "inspected": True,
        "redirections": redirections,
        "ssl": ssl_info,
        "whois": whois_info
    }
    
    # 3. Score de Riesgo Unificado
    risk_result = calculate_unified_risk(url_analysis, {"analyzed": False}, infra_analysis)
    
    # Guardar en base de datos
    client_ip = request.client.host if request.client else "127.0.0.1"
    save_threat_report(
        input_type="url",
        target_url=url,
        message_content="",
        risk_score=risk_result["unified_risk_score"],
        verdict=risk_result["verdict"],
        entity_targeted="Dominio Web",
        attack_type="Suplantación de Dominio / Typosquatting",
        macrodistrito=req.macrodistrito,
        factors=risk_result["factors"],
        whois_age_days=whois_info.get("age_days"),
        ssl_issuer=ssl_info.get("issuer"),
        client_ip=client_ip
    )
    
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "risk_score": risk_result["unified_risk_score"],
        "verdict": risk_result["verdict"],
        "factors": risk_result["factors"],
        "forensics": {
            "ml_probability": round(ml_prob * 100, 1),
            "redirections": redirections,
            "ssl_audit": ssl_info,
            "whois": whois_info
        },
        "stats": get_la_paz_threat_statistics()
    }

@app.post("/api/v1/analyze-message")
async def api_analyze_message(req: AnalyzeMessageRequest, request: Request):
    """
    Análisis de NLP de Mensajes (SMS / WhatsApp / Telegram)
     - Clasificación TF-IDF + Logistic Regression
     - NER de entidades bolivianas (Banco Unión, Yape, GAMLP, etc.)
     - Detección de vectores de ataque y urgencia psicológica
     - Detección de números extranjeros
    """
    msg = req.message.strip()
    if not msg:
        raise HTTPException(status_code=400, detail="Debe ingresar un mensaje para analizar.")
        
    nlp_data = analyze_message_content(msg)
    heuristic_factors = get_message_risk_factors(msg)
    
    # Unir factores detectados por NLP + heurísticas
    all_factors = heuristic_factors.copy()
    if nlp_data.get("foreign_phone_detected"):
        all_factors.append("Remitente con número internacional no boliviano fingiendo ser entidad local.")
        
    msg_analysis = {
        "analyzed": True,
        "raw_ml_prob": nlp_data["ml_prob"],
        "factors": all_factors
    }
    
    risk_result = calculate_unified_risk({"analyzed": False}, msg_analysis, {"inspected": False})
    
    client_ip = request.client.host if request.client else "127.0.0.1"
    save_threat_report(
        input_type="message",
        target_url="",
        message_content=msg,
        risk_score=risk_result["unified_risk_score"],
        verdict=risk_result["verdict"],
        entity_targeted=nlp_data.get("entity_targeted") or "No identificada",
        attack_type=nlp_data.get("attack_type") or "Ingeniería Social",
        macrodistrito=req.macrodistrito,
        factors=risk_result["factors"],
        client_ip=client_ip
    )
    
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": risk_result["unified_risk_score"],
        "verdict": risk_result["verdict"],
        "factors": risk_result["factors"],
        "entity_targeted": nlp_data.get("entity_targeted"),
        "attack_type": nlp_data.get("attack_type"),
        "triggers_found": nlp_data.get("detected_triggers"),
        "ml_probability": round(nlp_data["ml_prob"] * 100, 1),
        "stats": get_la_paz_threat_statistics()
    }

@app.post("/api/v1/analyze-image")
async def api_analyze_image(
    file: UploadFile = File(...),
    macrodistrito: str = Form("No especificado"),
    request: Request = None
):
    """
    Análisis Multimodal de Capturas de Pantalla (OCR + NLP + URL):
     - Extrae texto con OCR.
     - Extrae URLs contenidas en la captura.
     - Ejecuta el pipeline combinado.
    """
    image_bytes = await file.read()
    ocr_result = extract_text_from_image(image_bytes)
    
    extracted_text = ocr_result.get("text", "")
    found_urls = ocr_result.get("found_urls", [])
    
    # Analizar el texto extraído
    nlp_data = analyze_message_content(extracted_text) if extracted_text else {"ml_prob": 0.0, "detected_triggers": []}
    msg_factors = get_message_risk_factors(extracted_text) if extracted_text else []
    
    msg_analysis = {
        "analyzed": bool(extracted_text),
        "raw_ml_prob": nlp_data.get("ml_prob", 0.0),
        "factors": msg_factors
    }
    
    # Si encontró URL en la captura, analizar la primera
    url_analysis = {"analyzed": False}
    infra_analysis = {"inspected": False}
    target_url = found_urls[0] if found_urls else None
    
    if target_url:
        parsed = urlparse(target_url if target_url.startswith(("http://", "https://")) else "http://" + target_url)
        hostname = parsed.hostname or ""
        lexical = get_url_risk_factors(target_url)
        url_analysis = {"analyzed": True, "raw_ml_prob": 0.8, "factors": lexical}
        
        redirs = follow_redirections(target_url)
        ssl_info = inspect_ssl_certificate(hostname) if parsed.scheme == "https" else {"has_ssl": False}
        whois_info = inspect_whois_domain(hostname)
        infra_analysis = {"inspected": True, "redirections": redirs, "ssl": ssl_info, "whois": whois_info}
        
    risk_result = calculate_unified_risk(url_analysis, msg_analysis, infra_analysis)
    
    client_ip = request.client.host if request.client else "127.0.0.1"
    save_threat_report(
        input_type="image",
        target_url=target_url,
        message_content=extracted_text,
        risk_score=risk_result["unified_risk_score"],
        verdict=risk_result["verdict"],
        entity_targeted=nlp_data.get("entity_targeted") or "Captura de Pantalla",
        attack_type=nlp_data.get("attack_type") or "Fraude Visual / Smishing",
        macrodistrito=macrodistrito,
        factors=risk_result["factors"],
        client_ip=client_ip
    )
    
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ocr_text": extracted_text,
        "found_urls": found_urls,
        "risk_score": risk_result["unified_risk_score"],
        "verdict": risk_result["verdict"],
        "factors": risk_result["factors"],
        "entity_targeted": nlp_data.get("entity_targeted"),
        "attack_type": nlp_data.get("attack_type"),
        "stats": get_la_paz_threat_statistics()
    }

@app.get("/api/v1/threat-map")
async def api_threat_map():
    """Retorna estadísticas comunitarias georreferenciadas de La Paz."""
    stats = get_la_paz_threat_statistics()
    recent = get_recent_reports(limit=20)
    return {
        "macrodistritos": MACRODISTRITOS_LA_PAZ,
        "statistics": stats,
        "recent_incidents": recent
    }

# ── Endpoints Compatibles con Versión 1 ───────────────────────────

@app.post("/api/analyze")
async def analyze_legacy(req: LegacyAnalyzeRequest, request: Request):
    """Endpoint unificado compatible con el frontend existente."""
    url = req.url.strip() if req.url else None
    msg = req.message.strip() if req.message else None
    
    if not url and not msg:
        raise HTTPException(status_code=400, detail="Debe ingresar una URL o un mensaje.")
        
    url_analysis = {"analyzed": False, "raw_ml_prob": 0.0, "factors": []}
    infra_analysis = {"inspected": False}
    
    if url:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
        hostname = parsed.hostname or ""
        ml_prob = 0.0
        if url_model is not None:
            try:
                feats = extract_url_features(url)
                ml_prob = float(url_model.predict_proba([feats])[0][1])
            except Exception:
                ml_prob = 0.5
        url_analysis = {
            "analyzed": True,
            "raw_ml_prob": ml_prob,
            "factors": get_url_risk_factors(url)
        }
        # Inspección técnica de infraestructura
        redirs = follow_redirections(url)
        ssl_info = inspect_ssl_certificate(hostname) if parsed.scheme == "https" or url.startswith("https") else {"has_ssl": False}
        whois_info = inspect_whois_domain(hostname)
        infra_analysis = {"inspected": True, "redirections": redirs, "ssl": ssl_info, "whois": whois_info}
        
    msg_analysis = {"analyzed": False, "raw_ml_prob": 0.0, "factors": []}
    nlp_data = {}
    if msg:
        nlp_data = analyze_message_content(msg)
        factors = get_message_risk_factors(msg)
        if nlp_data.get("foreign_phone_detected"):
            factors.append("Número de contacto extranjero no boliviano (+591)")
        msg_analysis = {
            "analyzed": True,
            "raw_ml_prob": nlp_data.get("ml_prob", 0.0),
            "factors": factors
        }
        
    risk_result = calculate_unified_risk(url_analysis, msg_analysis, infra_analysis)
    
    client_ip = request.client.host if request.client else "127.0.0.1"
    save_threat_report(
        input_type="url+message" if url and msg else ("url" if url else "message"),
        target_url=url,
        message_content=msg,
        risk_score=risk_result["unified_risk_score"],
        verdict=risk_result["verdict"],
        entity_targeted=nlp_data.get("entity_targeted") or "Entidad Bancaria/Pública",
        attack_type=nlp_data.get("attack_type") or "Phishing/Smishing",
        macrodistrito=req.macrodistrito,
        factors=risk_result["factors"],
        whois_age_days=infra_analysis.get("whois", {}).get("age_days"),
        ssl_issuer=infra_analysis.get("ssl", {}).get("issuer"),
        client_ip=client_ip
    )
    
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": risk_result["unified_risk_score"],
        "verdict": risk_result["verdict"],
        "factors": risk_result["factors"],
        "entity_targeted": nlp_data.get("entity_targeted"),
        "attack_type": nlp_data.get("attack_type"),
        "details": {
            "url_analyzed": url_analysis["analyzed"],
            "url_risk_probability": round(url_analysis["raw_ml_prob"] * 100, 1),
            "message_analyzed": msg_analysis["analyzed"],
            "message_risk_probability": round(msg_analysis["raw_ml_prob"] * 100, 1),
            "forensics": infra_analysis if infra_analysis["inspected"] else None
        },
        "stats": get_la_paz_threat_statistics()
    }

@app.get("/api/history")
async def history():
    """Historial reciente."""
    records = get_recent_reports(limit=15)
    stats = get_la_paz_threat_statistics()
    return {"history": records, "stats": stats}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True, log_level="info")
