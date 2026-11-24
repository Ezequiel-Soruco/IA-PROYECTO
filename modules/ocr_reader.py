"""
modules/ocr_reader.py - Procesamiento y Extracción de Texto de Capturas de Pantalla (OCR)
Permite subir capturas de WhatsApp, SMS o correos para análisis directo.
"""

import re
from io import BytesIO
from PIL import Image

# Intentar usar pytesseract
try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

def extract_text_from_image(image_bytes: bytes) -> dict:
    """
    Recibe los bytes de una imagen y extrae el texto usando OCR.
    Extrae además cualquier URL encontrada dentro del texto reconocido.
    """
    try:
        image = Image.open(BytesIO(image_bytes))
        
        # Preprocesamiento básico: convertir a escala de grises para mejorar OCR
        gray_image = image.convert('L')
        
        extracted_text = ""
        if PYTESSERACT_AVAILABLE:
            try:
                # Intentar primero con español, luego con default
                extracted_text = pytesseract.image_to_string(gray_image, lang='spa+eng')
            except Exception:
                extracted_text = pytesseract.image_to_string(gray_image)
        else:
            extracted_text = "Módulo OCR no disponible en el sistema. Ingrese el texto manualmente."
            
        extracted_text = extracted_text.strip()
        
        # Buscar URLs en el texto extraído
        url_pattern = re.compile(
            r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-&?=%.]+',
            re.IGNORECASE
        )
        found_urls = []
        for match in url_pattern.findall(extracted_text):
            if '.' in match and len(match) > 4 and not match.endswith('.'):
                # Descartar falsos positivos comunes
                if not match.lower().startswith(('jpg', 'png', 'jpeg', 'pdf')):
                    found_urls.append(match)
                    
        return {
            "success": True,
            "text": extracted_text,
            "characters_count": len(extracted_text),
            "found_urls": list(set(found_urls))
        }
    except Exception as e:
        return {
            "success": False,
            "text": "",
            "error": str(e),
            "found_urls": []
        }
