"""
core/risk_engine.py - Motor de Score de Riesgo Unificado Ponderado (0 a 100%)
Integra:
 - ML de URL y Léxico (Levenshtein, Entropía Shannon, HTTPS).
 - NLP y NER (Urgencia, Entidad suplantada, vectores bolivianos).
 - Infraestructura Técnica Web (Antigüedad WHOIS, Auditoría SSL, Redirecciones).
"""

from typing import Dict, Any, List

def calculate_unified_risk(
    url_analysis: Dict[str, Any],
    msg_analysis: Dict[str, Any],
    infra_analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calcula el Score de Riesgo Unificado (0 a 100%) con explicabilidad técnica de ciberseguridad.
    """
    factors = []
    base_scores = []
    
    # ── 1. EVALUACIÓN DE INFRAESTRUCTURA (OSINT/RED) ───────────────
    infra_score = 0.0
    if infra_analysis.get("inspected"):
        whois_data = infra_analysis.get("whois", {})
        ssl_data = infra_analysis.get("ssl", {})
        redir_data = infra_analysis.get("redirections", {})
        
        # A) Antigüedad del Dominio
        age_days = whois_data.get("age_days")
        if age_days is not None:
            if age_days < 15:
                infra_score += 40
                factors.append(f"CRÍTICO: Dominio registrado hace apenas {age_days} días (típico de campañas de phishing efímeras).")
            elif age_days < 60:
                infra_score += 20
                factors.append(f"Dominio reciente ({age_days} días de antigüedad).")
            else:
                factors.append(f"Dominio establecido ({age_days} días de antigüedad).")
                
        # B) Auditoría SSL/TLS
        if not ssl_data.get("has_ssl", True):
            infra_score += 35
            factors.append("ALERTA TÉCNICA: El sitio carece de cifrado SSL/TLS (tráfico no cifrado).")
        else:
            issuer = ssl_data.get("issuer", "")
            if ssl_data.get("is_free_or_automated"):
                infra_score += 15
                factors.append(f"Certificado SSL automatizado/gratuito ({issuer}) en sitio que requiere confianza bancaria.")
                
        # C) Cadenas de Redirección Ocultas
        hops_count = redir_data.get("redirects_count", 0)
        if hops_count > 0:
            infra_score += min(25, hops_count * 10)
            factors.append(f"Se detectaron {hops_count} saltos de redirección HTTP para enmascarar el destino final.")
            
        # D) Cabeceras de Seguridad Faltantes
        sec_headers = redir_data.get("security_headers", {})
        if not sec_headers.get("content_security_policy") and not sec_headers.get("strict_transport_security"):
            infra_score += 10
            factors.append("Ausencia de cabeceras defensivas modernas (sin CSP ni HSTS).")
            
        base_scores.append(min(100.0, infra_score))

    # ── 2. EVALUACIÓN LÉXICA Y MODELO ML DE URL ─────────────────────
    if url_analysis.get("analyzed"):
        url_ml_prob = url_analysis.get("raw_ml_prob", 0.0) * 100.0
        base_scores.append(url_ml_prob)
        # Añadir factores léxicos ya detectados (Typosquatting, Shannon, IP, etc.)
        for f in url_analysis.get("factors", []):
            if f not in factors:
                factors.append(f)

    # ── 3. EVALUACIÓN SEMÁNTICA Y MODELO NLP ───────────────────────
    if msg_analysis.get("analyzed"):
        msg_ml_prob = msg_analysis.get("raw_ml_prob", 0.0) * 100.0
        base_scores.append(msg_ml_prob)
        for f in msg_analysis.get("factors", []):
            if f not in factors:
                factors.append(f)
                
    # ── 4. CONVERGENCIA Y PONDERACIÓN DEL SCORE UNIFICADO ───────────
    if not base_scores:
        final_score = 0.0
    elif len(base_scores) == 1:
        final_score = base_scores[0]
    else:
        # Ponderación donde el factor más riesgoso tiene mayor peso (Worst-Case Multi-Factor)
        max_score = max(base_scores)
        avg_others = (sum(base_scores) - max_score) / (len(base_scores) - 1)
        final_score = (max_score * 0.70) + (avg_others * 0.30)
        
    # Bonus crítico por combinación de vectores
    has_typosquatting = any("Typosquatting" in f for f in factors)
    has_credentials_request = any("Solicitud de datos sensibles" in f or "PIN" in f for f in factors)
    has_recent_domain = any("Dominio registrado hace apenas" in f for f in factors)
    
    if (has_typosquatting and has_credentials_request) or (has_recent_domain and has_credentials_request):
        final_score = max(final_score, 92.0)
        factors.insert(0, "🚨 VECTOR COMBINADO DE ALTA PROBABILIDAD: Suplantación de identidad activa con captura de credenciales.")

    final_score = round(min(100.0, max(0.0, final_score)), 1)
    
    # Determinación de Veredicto
    if final_score >= 65.0:
        verdict = "PELIGROSO (PHISHING)"
    elif final_score >= 35.0:
        verdict = "SOSPECHOSO"
    else:
        verdict = "SEGURO"
        
    if not factors:
        if final_score <= 30:
            factors.append("No se detectaron anomalías estructurales ni de infraestructura.")
        else:
            factors.append("El modelo estadístico detectó patrones anómalos no categorizados.")

    return {
        "unified_risk_score": final_score,
        "verdict": verdict,
        "factors": factors
    }
