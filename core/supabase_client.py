"""
core/supabase_client.py - Gestión de Persistencia Híbrida: Supabase (PostgreSQL) + Fallback SQLite
Almacena historial, lista blanca oficial de Bolivia y reportes georreferenciados en La Paz.
"""

import json
import sqlite3
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional

from config import SUPABASE_URL, SUPABASE_KEY, SQLITE_DB_PATH

supabase_client = None

if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception:
        supabase_client = None

def init_local_sqlite():
    """Inicializa la base de datos local SQLite con soporte para georreferenciación."""
    conn = sqlite3.connect(str(SQLITE_DB_PATH))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            input_type TEXT NOT NULL,
            target_url TEXT,
            message_content TEXT,
            risk_score REAL NOT NULL,
            verdict TEXT NOT NULL,
            entity_targeted TEXT,
            attack_type TEXT,
            macrodistrito TEXT,
            factors TEXT,
            whois_age_days INTEGER,
            ssl_issuer TEXT,
            ip_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

init_local_sqlite()

def save_threat_report(
    input_type: str,
    target_url: Optional[str],
    message_content: Optional[str],
    risk_score: float,
    verdict: str,
    entity_targeted: Optional[str],
    attack_type: Optional[str],
    macrodistrito: Optional[str],
    factors: List[str],
    whois_age_days: Optional[int] = None,
    ssl_issuer: Optional[str] = None,
    client_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Guarda el reporte en Supabase si está disponible; de lo contrario, lo guarda en SQLite local.
    """
    ip_hash = hashlib.sha256((client_ip or "127.0.0.1").encode()).hexdigest()[:16]
    now_iso = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Intentar en Supabase
    if supabase_client is not None:
        try:
            payload = {
                "input_type": input_type,
                "target_url": target_url or "",
                "message_content": (message_content[:250] + "...") if message_content and len(message_content) > 250 else (message_content or ""),
                "risk_score": float(risk_score),
                "verdict": verdict,
                "entity_targeted": entity_targeted or "No identificada",
                "attack_type": attack_type or "General",
                "macrodistrito": macrodistrito or "No especificado",
                "factors": factors,
                "whois_age_days": whois_age_days,
                "ssl_issuer": ssl_issuer or "",
                "ip_hash": ip_hash
            }
            res = supabase_client.table("threat_reports").insert(payload).execute()
            if res.data:
                return {"storage": "supabase", "id": res.data[0].get("id")}
        except Exception:
            pass  # Fallback a SQLite
            
    # 2. Fallback SQLite
    conn = sqlite3.connect(str(SQLITE_DB_PATH))
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threat_reports
        (created_at, input_type, target_url, message_content, risk_score, verdict,
         entity_targeted, attack_type, macrodistrito, factors, whois_age_days, ssl_issuer, ip_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now_iso,
        input_type,
        target_url or "",
        (message_content[:250] + "...") if message_content and len(message_content) > 250 else (message_content or ""),
        float(risk_score),
        verdict,
        entity_targeted or "No identificada",
        attack_type or "General",
        macrodistrito or "No especificado",
        json.dumps(factors, ensure_ascii=False),
        whois_age_days,
        ssl_issuer or "",
        ip_hash
    ))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"storage": "sqlite", "id": report_id}

def get_recent_reports(limit: int = 15) -> List[Dict[str, Any]]:
    """Obtiene los últimos reportes registrados."""
    # Probar primero en Supabase
    if supabase_client is not None:
        try:
            res = supabase_client.table("threat_reports").select("*").order("id", desc=True).limit(limit).execute()
            if res.data:
                return res.data
        except Exception:
            pass
            
    # Fallback SQLite
    conn = sqlite3.connect(str(SQLITE_DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM threat_reports
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "input_type": r["input_type"],
            "target_url": r["target_url"],
            "message_content": r["message_content"],
            "risk_score": r["risk_score"],
            "verdict": r["verdict"],
            "entity_targeted": r["entity_targeted"],
            "attack_type": r["attack_type"],
            "macrodistrito": r["macrodistrito"],
            "factors": json.loads(r["factors"]) if r["factors"] else []
        })
    return results

def get_la_paz_threat_statistics() -> Dict[str, Any]:
    """
    Calcula estadísticas en tiempo real por Macrodistrito de La Paz y Top Entidades Suplantadas.
    """
    conn = sqlite3.connect(str(SQLITE_DB_PATH))
    cursor = conn.cursor()
    
    # Total y clasificaciones
    cursor.execute("SELECT COUNT(*) FROM threat_reports")
    total = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM threat_reports WHERE verdict = 'PELIGROSO (PHISHING)'")
    blocked = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM threat_reports WHERE verdict = 'SOSPECHOSO'")
    suspicious = cursor.fetchone()[0] or 0
    
    # Distribución por Macrodistrito de La Paz
    cursor.execute("""
        SELECT macrodistrito, COUNT(*) as qty
        FROM threat_reports
        WHERE macrodistrito IS NOT NULL AND macrodistrito != 'No especificado'
        GROUP BY macrodistrito
        ORDER BY qty DESC
    """)
    macro_rows = cursor.fetchall()
    by_macrodistrito = {r[0]: r[1] for r in macro_rows}
    
    # Top 5 Entidades Bolivianas atacadas
    cursor.execute("""
        SELECT entity_targeted, COUNT(*) as qty
        FROM threat_reports
        WHERE entity_targeted IS NOT NULL AND entity_targeted != 'No identificada'
        GROUP BY entity_targeted
        ORDER BY qty DESC
        LIMIT 5
    """)
    entity_rows = cursor.fetchall()
    top_entities = [{"entity": r[0], "count": r[1]} for r in entity_rows]
    
    conn.close()
    
    return {
        "total_scanned": total,
        "threats_blocked": blocked,
        "suspicious_count": suspicious,
        "safe_count": max(0, total - blocked - suspicious),
        "by_macrodistrito": by_macrodistrito,
        "top_entities": top_entities
    }
