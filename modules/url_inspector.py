"""
modules/url_inspector.py - Motor Forense OSINT y Análisis Técnico de Infraestructura Web
Inspecciona:
 1. Redirecciones HTTP (301/302) y cabeceras de seguridad.
 2. Antigüedad del Dominio mediante WHOIS / RDAP.
 3. Auditoría de Certificados SSL/TLS (Emisor, Validez, Fechas).
 4. Resolución DNS de direcciones IP y reputación técnica.
"""

import socket
import ssl
import datetime
from urllib.parse import urlparse
import requests
import whois
import tldextract

def follow_redirections(url: str, timeout: int = 5) -> dict:
    """
    Sigue de forma segura las cadenas de redirección HTTP sin descargar contenido peligroso.
    """
    history_hops = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 EscudoDigitalLaPaz/2.0"
    }
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    try:
        session = requests.Session()
        # Solo HEAD o GET con stream=True para no cargar malware
        response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True)
        
        # Historial de saltos
        if response.history:
            for resp in response.history:
                history_hops.append({
                    "status_code": resp.status_code,
                    "url": resp.url
                })
        
        final_url = response.url
        security_headers = {
            "x_frame_options": response.headers.get("X-Frame-Options"),
            "content_security_policy": bool(response.headers.get("Content-Security-Policy")),
            "strict_transport_security": bool(response.headers.get("Strict-Transport-Security"))
        }
        
        return {
            "success": True,
            "final_url": final_url,
            "redirects_count": len(history_hops),
            "hops": history_hops,
            "security_headers": security_headers
        }
    except Exception as e:
        return {
            "success": False,
            "final_url": url,
            "redirects_count": 0,
            "hops": [],
            "error": str(e)
        }

def inspect_ssl_certificate(hostname: str, port: int = 443, timeout: int = 4) -> dict:
    """
    Audita el certificado SSL/TLS del host destino:
    - Entidad emisora (CA): Let's Encrypt vs EV corporativa.
    - Días restantes de expiración.
    - Protocolo negociado.
    """
    if not hostname:
        return {"has_ssl": False, "error": "Hostname vacío"}
        
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Para poder inspeccionar certificados auto-firmados o sospechosos
    
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Para detalles en CERT_NONE, leemos información disponible
                issuer_dict = {}
                subject_dict = {}
                not_after = None
                not_before = None
                
                # Intentar con handshake estricto
                try:
                    strict_context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=timeout) as sock2:
                        with strict_context.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                            full_cert = ssock2.getpeercert()
                            for item in full_cert.get('issuer', []):
                                for k, v in item:
                                    issuer_dict[k] = v
                            for item in full_cert.get('subject', []):
                                for k, v in item:
                                    subject_dict[k] = v
                            not_after = full_cert.get('notAfter')
                            not_before = full_cert.get('notBefore')
                except Exception:
                    pass

                ca_name = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or "Desconocida/Auto-firmada"
                
                is_free_ca = any(free in ca_name.lower() for free in ["let's encrypt", "zerossl", "cpanel", "cloudflare"])
                
                days_valid = None
                if not_after:
                    try:
                        exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_valid = (exp_date - datetime.datetime.utcnow()).days
                    except Exception:
                        pass

                return {
                    "has_ssl": True,
                    "issuer": ca_name,
                    "is_free_or_automated": is_free_ca,
                    "days_until_expiration": days_valid,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else None,
                    "subject": subject_dict.get('commonName', hostname)
                }
    except Exception as e:
        return {
            "has_ssl": False,
            "error": str(e)
        }

def inspect_whois_domain(hostname: str) -> dict:
    """
    Consulta la fecha de creación del dominio para determinar la antigüedad en días.
    Los dominios de phishing suelen tener < 30 días de vida.
    """
    ext = tldextract.extract(hostname)
    registered_domain = f"{ext.domain}.{ext.suffix}"
    
    if not ext.domain or not ext.suffix:
        return {"success": False, "age_days": None, "error": "No se pudo extraer dominio registrado"}
        
    try:
        w = whois.whois(registered_domain)
        creation_date = w.creation_date
        
        # En ocasiones devuelve una lista de fechas
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            now = datetime.datetime.now()
            age_days = (now - creation_date).days
            return {
                "success": True,
                "registered_domain": registered_domain,
                "creation_date": creation_date.strftime("%Y-%m-%d"),
                "age_days": max(0, age_days),
                "registrar": w.registrar or "No especificado",
                "is_very_recent": age_days < 30
            }
        else:
            return {
                "success": False,
                "registered_domain": registered_domain,
                "age_days": None,
                "error": "Fecha de creación no expuesta por el registrador"
            }
    except Exception as e:
        return {
            "success": False,
            "registered_domain": registered_domain,
            "age_days": None,
            "error": str(e)
        }
