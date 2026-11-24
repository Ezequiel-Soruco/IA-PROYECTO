# 🛡️ Escudo Digital La Paz
## Sistema Web Inteligente Anti-Phishing y Detección de Fraude Digital con IA

> **Proyecto de Tesis** | La Paz, Bolivia | 2024
> Sistema contextualizado a entidades financieras, gubernamentales y de telecomunicaciones bolivianas.

---

## 📋 Descripción

**Escudo Digital La Paz** es una aplicación web de ciberseguridad que utiliza modelos de Machine Learning e Inteligencia Artificial para detectar en tiempo real ataques de **phishing**, **smishing** y **suplantación de identidad** dirigidos a usuarios bolivianos.

### Entidades monitoreadas
- 🏦 **Banca**: Banco Unión, BNB, Banco Mercantil Santa Cruz (BMSC)
- 💳 **Fintech**: Yape Bolivia, Tigo Money
- 🏛️ **Gobierno**: GAMLP, Impuestos Nacionales (SIN), SEGIP, DeLaPaz
- 📡 **Telecomunicaciones**: Entel Bolivia

---

## 🏗️ Arquitectura del Sistema

```
iaProyecto/
├── app.py              ← Servidor FastAPI (backend + endpoints)
├── train_model.py      ← Entrenamiento de modelos ML
├── features.py         ← Extracción de características + heurísticas
├── requirements.txt    ← Dependencias Python
├── templates/
│   └── index.html      ← Interfaz web (modo oscuro SOC/Cyber)
├── models/             ← Modelos entrenados (generados por train_model.py)
│   ├── url_model.pkl
│   ├── message_model.pkl
│   └── dataset_info.json
└── escudo_digital.db   ← Base de datos SQLite (generada automáticamente)
```

---

## ⚙️ Stack Tecnológico

| Capa | Tecnología |
|------|-----------|
| Backend | Python 3.10+ · FastAPI · Uvicorn |
| ML/NLP | scikit-learn · RandomForest · TF-IDF · LogisticRegression |
| Análisis URL | Levenshtein · Entropía Shannon · Reglas heurísticas |
| Base de datos | SQLite (historial de análisis) |
| Frontend | HTML5 · TailwindCSS (CDN) · JavaScript ES6+ |
| Serialización | joblib (modelos ML) |

---

## 🚀 Instrucciones de Instalación y Ejecución

### Requisitos previos
- Python 3.10 o superior
- pip o pip3

### Paso 1: Clonar/navegar al proyecto
```bash
cd iaProyecto
```

### Paso 2: Crear entorno virtual (recomendado)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Paso 3: Instalar dependencias
```bash
pip install -r requirements.txt
```

### Paso 4: Entrenar los modelos de IA
```bash
python train_model.py
```
Esto generará en `models/`:
- `url_model.pkl` — RandomForestClassifier (15 características de URL)
- `message_model.pkl` — Pipeline TF-IDF + LogisticRegression

### Paso 5: Iniciar el servidor web
```bash
python app.py
```
O con Uvicorn directamente:
```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

### Paso 6: Abrir en el navegador
```
http://127.0.0.1:8000
```

---

## 🔌 Endpoints de la API

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/` | Interfaz web principal |
| `POST` | `/api/analyze` | Analiza URL y/o mensaje |
| `GET` | `/api/history` | Últimos 15 análisis |
| `GET` | `/api/health` | Estado del sistema y modelos |

### Ejemplo de uso — `/api/analyze`

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://bancounion-seguro.com/verificar",
    "message": "URGENTE: Su cuenta fue BLOQUEADA. Verifique ahora."
  }'
```

**Respuesta:**
```json
{
  "timestamp": "2024-11-22 20:00:00",
  "risk_score": 92.5,
  "verdict": "PELIGROSO (PHISHING)",
  "factors": [
    "URL excesivamente larga (43 caracteres) — táctica común de ofuscación",
    "Typosquatting detectado: 'bancounion-seguro.com' imita a 'bancounion.com.bo' (distancia Levenshtein = 2)",
    "No usa HTTPS — la conexión no es segura ni verificada",
    "Lenguaje de urgencia/presión detectado: 'urgente'",
    "Solicitud de datos sensibles: 'verificar'"
  ],
  "details": {
    "url_analyzed": true,
    "url_risk_probability": 95.2,
    "message_analyzed": true,
    "message_risk_probability": 88.1
  }
}
```

---

## 🤖 Modelos de Machine Learning

### Modelo de URLs — RandomForestClassifier
**15 características extraídas:**
1. Longitud total de la URL
2. Longitud del hostname
3. Entropía de Shannon (detección de DGA)
4. Número de subdominios
5. Número de guiones en hostname
6. Número de dígitos en hostname
7. Presencia de `@` en la URL
8. Presencia de `?` en la URL
9. Presencia de `=` en la URL
10. Porcentaje de codificación `%`
11. Hostname es dirección IP (0/1)
12. Uso de HTTPS (0/1)
13. Distancia Levenshtein a dominio boliviano oficial
14. Longitud del path
15. Número de puntos en hostname

### Modelo de Mensajes — TF-IDF + LogisticRegression
- **Vectorizador**: TF-IDF con n-gramas (1,3), 8,000 features
- **Clasificador**: Regresión Logística con balance de clases
- Dataset: mensajes legítimos vs. phishing/smishing contextualizados a Bolivia

### Heurísticas adicionales (explicabilidad)
- Detección de **typosquatting** via Levenshtein contra dominios oficiales `.bo`
- Análisis de **entropía Shannon** para detectar dominios DGA (aleatorios)
- Patrones de **urgencia** y **señuelos** contextualizados a Bolivia
- Detección de **solicitud de credenciales** sensibles
- Identificación de **entidades bolivianas suplantadas**

---

## 📊 Dataset Sintético

| Dataset | Legítimas | Phishing | Total (con augm.) |
|---------|-----------|----------|-------------------|
| URLs | 50+ | 50+ | ~300 |
| Mensajes | 40+ | 35+ | ~225 |

**Contexto boliviano cubierto:**
- Suplantación bancaria (Banco Unión, BNB, BMSC)
- Fraudes Yape/Tigo Money
- Bonos y subsidios falsos del gobierno
- Multas municipales falsas (GAMLP)
- Phishing de SEGIP, Impuestos Nacionales
- Ofertas falsas de Entel, Tigo, Viva

---

## 🛡️ Características de Seguridad Detectadas

| Técnica | Descripción |
|---------|-------------|
| **Phishing de URL** | URLs con typosquatting de dominios bolivianos |
| **IP en URL** | Hostname es dirección IP directa |
| **Subdominios excesivos** | Enmascaramiento del dominio real |
| **DGA** | Dominios generados aleatoriamente (alta entropía) |
| **Smishing** | Mensajes SMS/WhatsApp con señuelos bolivianos |
| **Urgency Baiting** | Lenguaje de presión y urgencia artificial |
| **Credential Phishing** | Solicitud directa de contraseñas, PINs, CI |
| **Prize/Bono Scam** | Señuelos de premios y bonos gubernamentales falsos |
| **Multa/Deuda Falsa** | Amenazas de multas o deudas inexistentes |

---

## 👨‍💻 Contribución al Proyecto de Tesis

Este sistema demuestra la aplicación práctica de:
- **Machine Learning supervisado** en ciberseguridad
- **NLP** para clasificación de texto malicioso
- **Análisis forense de URLs** con múltiples features
- **Explicabilidad de IA** (factores detectados por regla)
- **Desarrollo web full-stack** con Python moderno
- **Contextualización local** del problema de phishing para Bolivia

---

*Escudo Digital La Paz — Protegiendo a los ciudadanos de La Paz del fraude digital.*
