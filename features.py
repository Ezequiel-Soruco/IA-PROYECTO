"""
features.py — Módulo de extracción de características de ciberseguridad para URLs.
Escudo Digital La Paz — Sistema Anti-Phishing con IA
"""

import math
import re
from urllib.parse import urlparse
from typing import List, Dict, Any

# Levenshtein: intentamos importar la librería nativa; si falla, usamos implementación propia
try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Implementación pura de distancia de Levenshtein como fallback."""
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]


# ─── Dominios oficiales reales de Bolivia ────────────────────────────────────
OFFICIAL_BOLIVIAN_DOMAINS = [
    "bancounion.com.bo",
    "bnb.com.bo",
    "bmsc.com.bo",           # Banco Mercantil Santa Cruz
    "lapaz.bo",
    "impuestos.gob.bo",
    "entel.bo",
    "delapaz.bo",
    "segip.gob.bo",
    "yape.com.bo",
    "tigomoney.com.bo",
    "gamlp.gob.bo",
    "gob.bo",
]

# Umbral de distancia de Levenshtein para detectar typosquatting
LEVENSHTEIN_THRESHOLD = 4


def shannon_entropy(text: str) -> float:
    """Calcula la entropía de Shannon de un string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def is_ip_address(hostname: str) -> bool:
    """Detecta si el hostname es una dirección IP (v4 o v4 en bruto)."""
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    return bool(ip_pattern.match(hostname))


def count_subdomains(hostname: str) -> int:
    """Cuenta el número de subdominios (puntos - 1 para TLD de 2 niveles como .com.bo)."""
    parts = hostname.split(".")
    # Bolivia usa TLD de 2 niveles: .com.bo, .gob.bo, .net.bo, etc.
    if len(parts) >= 2 and parts[-1] == "bo":
        # e.g. sub.banco.com.bo → partes = [sub, banco, com, bo] → 1 subdominio
        return max(0, len(parts) - 3)
    return max(0, len(parts) - 2)


def min_levenshtein_to_official(domain: str) -> Dict[str, Any]:
    """
    Calcula la mínima distancia de Levenshtein entre el dominio dado
    y todos los dominios oficiales de Bolivia.
    Retorna el dominio más cercano y la distancia.
    """
    domain_clean = domain.lower().strip()
    min_dist = float("inf")
    closest = ""
    for official in OFFICIAL_BOLIVIAN_DOMAINS:
        # Comparar solo la parte base del dominio oficial (sin TLD)
        official_base = official.split(".")[0]
        domain_base = domain_clean.split(".")[0]
        dist = levenshtein_distance(domain_base, official_base)
        if dist < min_dist:
            min_dist = dist
            closest = official
    return {"distance": int(min_dist), "closest_official": closest}


def extract_url_features(url: str) -> List[float]:
    """
    Extrae un vector de características numéricas de una URL para el modelo ML.

    Características extraídas (en orden):
     0. Longitud total de la URL
     1. Longitud del hostname
     2. Entropía de Shannon de la URL completa
     3. Número de subdominios
     4. Número de guiones en el hostname
     5. Número de dígitos en el hostname
     6. Número de caracteres '@' en la URL
     7. Número de caracteres '?' en la URL
     8. Número de caracteres '=' en la URL
     9. Número de caracteres '%' en la URL
    10. 1 si el hostname es una IP, 0 si no
    11. 1 si usa HTTPS, 0 si usa HTTP
    12. Distancia mínima de Levenshtein a dominio oficial boliviano
    13. Longitud del path
    14. Número de puntos en el hostname
    """
    # Sanitizar URL
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        full = url
    except Exception:
        hostname = ""
        path = ""
        full = url

    lev_info = min_levenshtein_to_official(hostname)

    features = [
        float(len(full)),                           # 0
        float(len(hostname)),                        # 1
        shannon_entropy(full),                       # 2
        float(count_subdomains(hostname)),           # 3
        float(hostname.count("-")),                  # 4
        float(sum(c.isdigit() for c in hostname)),   # 5
        float(full.count("@")),                      # 6
        float(full.count("?")),                      # 7
        float(full.count("=")),                      # 8
        float(full.count("%")),                      # 9
        float(1 if is_ip_address(hostname) else 0),  # 10
        float(1 if parsed.scheme == "https" else 0), # 11
        float(lev_info["distance"]),                 # 12
        float(len(path)),                            # 13
        float(hostname.count(".")),                  # 14
    ]
    return features


def get_url_risk_factors(url: str) -> List[str]:
    """
    Analiza una URL y retorna una lista legible de factores de riesgo detectados.
    Usado para la explicabilidad en el frontend.
    """
    factors = []
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url_check = "http://" + url
    else:
        url_check = url

    try:
        parsed = urlparse(url_check)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
    except Exception:
        hostname = ""
        path = ""

    # Chequeos individuales
    if len(url) > 75:
        factors.append(f"URL excesivamente larga ({len(url)} caracteres) — táctica común de ofuscación")

    if is_ip_address(hostname):
        factors.append(f"El hostname es una dirección IP ({hostname}) — sitios legítimos usan dominios")

    if parsed.scheme != "https":
        factors.append("No usa HTTPS — la conexión no es segura ni verificada")

    if hostname.count("-") >= 2:
        factors.append(f"Hostname con múltiples guiones ({hostname.count('-')}) — patrón de dominio fraudulento")

    if count_subdomains(hostname) >= 3:
        factors.append(f"Exceso de subdominios ({count_subdomains(hostname)}) — técnica de enmascaramiento")

    if url_check.count("@") > 0:
        factors.append("Carácter '@' en la URL — puede redirigir a otro servidor")

    if url_check.count("%") > 3:
        factors.append(f"Alta codificación URL ({url_check.count('%')} '%') — posible ofuscación")

    entropy = shannon_entropy(hostname)
    if entropy > 3.8:
        factors.append(f"Alta entropía del dominio ({entropy:.2f} bits) — posible dominio generado aleatoriamente (DGA)")

    lev_info = min_levenshtein_to_official(hostname)
    if 1 <= lev_info["distance"] <= LEVENSHTEIN_THRESHOLD:
        factors.append(
            f"Typosquatting detectado: '{hostname}' imita a '{lev_info['closest_official']}' "
            f"(distancia Levenshtein = {lev_info['distance']})"
        )

    # Palabras clave de phishing boliviano en la URL
    phishing_keywords = [
        "cuenta", "verificar", "actualizar", "login", "seguro", "banco",
        "premio", "bono", "multa", "urgente", "suspendida", "bloqueada",
        "yape", "tigo", "entel", "union", "bnb", "gamlp", "impuestos",
        "confirm", "verify", "secure", "update", "account", "password",
        "credencial", "clave", "token", "acceso"
    ]
    found_kw = [kw for kw in phishing_keywords if kw in url_check.lower()]
    if found_kw:
        factors.append(f"Palabras clave sospechosas en URL: {', '.join(found_kw[:5])}")

    if sum(c.isdigit() for c in hostname) > 4:
        factors.append(f"Muchos dígitos en el hostname ({sum(c.isdigit() for c in hostname)}) — patrón inusual")

    return factors


def get_message_risk_factors(message: str) -> List[str]:
    """
    Analiza un mensaje de texto (WhatsApp/SMS/Email) y retorna factores de riesgo.
    Reglas heurísticas contextualizadas a Bolivia.
    """
    factors = []
    msg_lower = message.lower()

    # Urgencia y presión
    urgency_patterns = [
        "urgente", "inmediatamente", "ahora mismo", "en las próximas",
        "su cuenta será", "será bloqueada", "será suspendida", "último aviso",
        "acción requerida", "acción inmediata", "verifique ahora"
    ]
    found_urgency = [p for p in urgency_patterns if p in msg_lower]
    if found_urgency:
        factors.append(f"Lenguaje de urgencia/presión detectado: '{found_urgency[0]}'")

    # Entidades bolivianas suplantadas
    bolivian_entities = {
        "banco unión": "Banco Unión",
        "bancounion": "Banco Unión",
        "bnb": "BNB",
        "banco bnb": "BNB",
        "mercantil santa cruz": "Banco Mercantil Santa Cruz",
        "yape": "Yape Bolivia",
        "tigo money": "Tigo Money",
        "gamlp": "GAMLP (Gobierno Municipal de La Paz)",
        "impuestos nacionales": "Impuestos Nacionales (SIN)",
        "sin bolivia": "SIN Bolivia",
        "entel": "Entel Bolivia",
        "segip": "SEGIP",
        "delapaz": "DeLaPaz",
        "bono": "Bono (programa social)",
    }
    found_entities = []
    for key, name in bolivian_entities.items():
        if key in msg_lower:
            found_entities.append(name)
    if found_entities:
        factors.append(f"Mención de entidades bolivianas: {', '.join(set(found_entities[:3]))} — verificar autenticidad")

    # Solicitud de datos sensibles
    sensitive_data = [
        "contraseña", "clave", "pin", "nit", "ci ", "carnet", "número de cuenta",
        "tarjeta", "cvv", "token", "código de verificación", "código sms",
        "datos personales", "credenciales", "usuario y", "password"
    ]
    found_sensitive = [p for p in sensitive_data if p in msg_lower]
    if found_sensitive:
        factors.append(f"Solicitud de datos sensibles: {', '.join(found_sensitive[:3])}")

    # Premios, bonos y multas falsas
    reward_patterns = [
        "ganó", "ganaste", "premio", "seleccionado", "regalo", "gratis",
        "bono extraordinario", "bono COVID", "bono juana azurduy", "doble aguinaldo",
        "multa pendiente", "deuda pendiente", "infracción", "cobro pendiente"
    ]
    found_rewards = [p for p in reward_patterns if p in msg_lower]
    if found_rewards:
        factors.append(f"Señuelo de premio/multa/bono falso: '{found_rewards[0]}'")

    # Links acortados o sospechosos
    short_links = ["bit.ly", "tinyurl", "t.co", "shorturl", "goo.gl", "ow.ly", "rb.gy", "cutt.ly"]
    found_links = [l for l in short_links if l in msg_lower]
    if found_links:
        factors.append(f"Link acortado detectado ({found_links[0]}) — oculta el destino real")

    # Números de teléfono extranjeros
    if re.search(r"\+(?!591)\d{10,}", message):
        factors.append("Número de teléfono con prefijo internacional no boliviano (+591)")

    # Errores ortográficos intencionales (patrón común)
    typo_patterns = ["banc0", "yap3", "entël", "b0no", "cuénta", "clàve"]
    found_typos = [t for t in typo_patterns if t in msg_lower]
    if found_typos:
        factors.append(f"Posibles errores tipográficos intencionales: {', '.join(found_typos)}")

    # URLs embebidas en el mensaje
    urls_in_msg = re.findall(r'https?://\S+|www\.\S+', message, re.IGNORECASE)
    if urls_in_msg:
        for u in urls_in_msg[:2]:
            parsed_u = urlparse(u if u.startswith("http") else "http://" + u)
            host = parsed_u.hostname or ""
            if not host.endswith(".bo") and host:
                factors.append(f"URL en mensaje no es dominio boliviano (.bo): {host}")

    return factors
