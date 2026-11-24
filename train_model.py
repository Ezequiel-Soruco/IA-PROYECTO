"""
train_model.py — Entrenamiento de modelos de ML para Escudo Digital La Paz
Genera dataset sintético contextualizado a Bolivia, entrena modelos y guarda en models/

Uso: python train_model.py
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.pipeline import Pipeline
import joblib
from features import extract_url_features

# ─── Configuración ────────────────────────────────────────────────────────────
MODELS_DIR = "models"
os.makedirs(MODELS_DIR, exist_ok=True)
np.random.seed(42)


# ═══════════════════════════════════════════════════════════════════════════════
#  DATASET DE URLs
# ═══════════════════════════════════════════════════════════════════════════════

LEGITIMATE_URLS = [
    # Bancos y fintech bolivianos reales
    "https://www.bancounion.com.bo/banca-en-linea",
    "https://www.bnb.com.bo/servicios/creditos",
    "https://www.bmsc.com.bo/personas/tarjetas",
    "https://yape.com.bo/inicio",
    "https://www.tigomoney.com.bo/transferencias",
    "https://www.bancofie.com.bo/ahorro",
    "https://www.bisa.com.bo/inversiones",
    "https://www.bancosol.com.bo/microempresa",
    "https://www.ecosur.com.bo/credito",
    "https://www.prodem.com.bo/inicio",
    # Gobierno y municipio
    "https://www.gamlp.gob.bo/ciudadano/tramites",
    "https://www.impuestos.gob.bo/declaraciones",
    "https://www.segip.gob.bo/registro",
    "https://www.lapaz.bo/noticias",
    "https://www.delapaz.bo/servicios",
    "https://www.gob.bo/tramites",
    "https://www.aduana.gob.bo/aranceles",
    "https://www.bcb.gob.bo/estadisticas",
    "https://www.ine.gob.bo/censo",
    "https://www.minedu.gob.bo/calendario",
    # Telecomunicaciones
    "https://www.entel.bo/hogar/internet",
    "https://www.tigo.com.bo/movil/planes",
    "https://www.viva.com.bo/recargas",
    # Noticias y comercio legítimo
    "https://www.paginasiete.bo/economia",
    "https://www.eldeber.com.bo/tecnologia",
    "https://www.lostiempos.com/bolivia",
    "https://www.correodelsur.com/la-paz",
    "https://www.feriabolivia.com/catalogo",
    "https://www.cotas.com.bo/internet",
    "https://www.amazon.com/products/electronics",
    "https://www.google.com/search?q=banco+union+bolivia",
    "https://www.youtube.com/watch?v=abc123",
    "https://www.facebook.com/bancounionbolivia",
    "https://support.google.com/accounts/help",
    "https://www.microsoft.com/es-bo/software",
    "https://portal.sat.gob.mx/portal/",
    "https://www.mercadolibre.com.bo/productos",
    "https://www.olx.com.bo/la-paz",
    "https://www.infocasas.com.bo/alquiler",
    "https://bancounion.com.bo/login",
    "https://bnb.com.bo/app",
    "https://www.gamlp.gob.bo/mapa-ciudad",
    "https://impuestos.gob.bo/formularios",
    "https://entel.bo/catalogo-celulares",
    "https://tigomoney.com.bo/app",
    "https://www.segip.gob.bo/duplicado-carnet",
    "https://yape.com.bo/como-usar",
    "https://www.lapaz.bo/turismo",
    "https://delapaz.bo/rutas",
    "https://bmsc.com.bo/banca-movil",
]

PHISHING_URLS = [
    # Typosquatting y suplantación de bancos bolivianos
    "http://bancounion-seguro.com/verificar-cuenta",
    "http://www.bnb-bolivia-login.com/acceso",
    "http://bmsc-actualizar.net/datos-cliente",
    "http://yape-bo-premio.com/reclamar-ahora",
    "http://tigomoney-verificar.xyz/cuenta",
    "http://banco-union-bo.com.mx/login",
    "http://bnb-segurobо.info/actualizar",
    "http://mercantilsantacruz-login.com/seguro",
    "http://yape-bo.tk/verificacion",
    "http://tigo-money-bo.ml/recargar",
    # IPs directas
    "http://192.168.1.1/banco-union/login",
    "http://10.0.0.1/bnb/seguridad",
    "http://203.45.123.67/phishing/banco",
    "http://185.220.101.5/update-account",
    "http://91.108.4.1/cuenta-bancaria",
    # Subdominios maliciosos
    "http://bancounion.seguro.verificar.phishing-site.com/login",
    "http://bnb.bolivia.update.malware.net/datos",
    "http://gamlp.municipio.tramites.fake-gov.com/pago",
    "http://impuestos.sin.bolivia.scam.tk/declarar",
    "http://segip.carnet.renewal.malicious.xyz/datos",
    # URLs largas y ofuscadas
    "http://www.banco-union-bolivia-verificar-cuenta-ahora-urgente.com/login?token=abc123&redirect=https://bancounion.com.bo",
    "http://bnb-banco-nacional-bolivia-cuenta-bloqueada-verificar.net/seguridad?session=xyz",
    "http://www.actualizar-datos-banco-mercantil-santa-cruz-bolivia.com/login",
    "http://yape-premio-100bs-reclamar-gratis-bolivia.ml/pago",
    "http://tigo-money-transferencia-gratuita-bolivia-ahora.tk/enviar",
    # Phishing de gobierno boliviano
    "http://gamlp-multa-pendiente.com/pagar-ahora",
    "http://impuestos-nacionales-bolivia.net/declaracion-urgente",
    "http://segip-renovar-carnet.xyz/datos-personales",
    "http://bono-juana-azurduy-cobrar.com/registro",
    "http://bono-contra-la-pobreza-bolivia.tk/solicitar",
    # URLs con caracteres especiales / codificación
    "http://banc%6Funion.com.bo.malicious.com/login",
    "http://bnb.c0m.bo/update@malicious.site",
    "http://www.banco%2Dunion%2Dbolivia.phish.com",
    "http://yap3-b0livia.com/cuenta",
    "http://t1go-m0ney.com/pago",
    # Entel y telecomunicaciones falsas
    "http://entel-bo-premio-datos-gratis.com/reclamar",
    "http://www.tigo-bo-recargas-gratis.ml/activar",
    "http://viva-bo-plan-gratis.tk/activar-ahora",
    # Subdominios muy profundos
    "http://secure.login.bancounion.com.phishing-attack.ru/datos",
    "http://update.account.bnb.com.bo.evil.com/login",
    "http://verify.seguro.gamlp.gob.bo.hacker.tk/pago",
    # Sitios con alta entropía (DGA simulado)
    "http://xk3f9p2mq.com/banco-union-bo",
    "http://a7b2c9d4e.net/bnb-login",
    "http://qz8w1r5ty.xyz/gamlp-tramite",
    "http://m3n6p0l2x.info/impuestos-bo",
    "http://j4k7v9u1b.tk/yape-cobro",
    # Más variantes de phishing boliviano
    "http://bancounion.com.bo.login.hacker.com",
    "http://bn-b-seguro.com/cuenta-bloqueada",
    "http://yapebol.com/verificar-identidad",
    "http://tigomoneybo.com/pago-pendiente",
    "http://gamlp-bo.com/multa-trafico",
]

assert len(LEGITIMATE_URLS) >= 50, "Se necesitan al menos 50 URLs legítimas"
assert len(PHISHING_URLS) >= 50, "Se necesitan al menos 50 URLs de phishing"


# ═══════════════════════════════════════════════════════════════════════════════
#  DATASET DE MENSAJES (SMS / WhatsApp / Email)
# ═══════════════════════════════════════════════════════════════════════════════

LEGITIMATE_MESSAGES = [
    # Banco Unión
    "Estimado cliente, su transferencia de Bs. 500 fue procesada exitosamente. Código: BU2024-001. Banco Unión.",
    "Su solicitud de crédito en Banco Unión ha sido aprobada. Visite su sucursal más cercana con su CI.",
    "Recordatorio: Su cuota mensual de Bs. 1,200 vence el 15 de este mes. Banco Unión.",
    "Bienvenido a Banca en Línea Banco Unión. Para soporte llame al 800-10-1234.",
    "Su saldo disponible en cuenta de ahorros es Bs. 3,450.00. Banco Unión.",
    # BNB
    "Transacción autorizada: Bs. 250.00 en BNB Tarjeta Visa terminada en 4521. BNB.",
    "Su estado de cuenta BNB de octubre está disponible. Descárguelo en nuestra app oficial.",
    "BNB informa: Nuestras oficinas abren de lunes a viernes de 8:30 a 16:30. Sin atención feriados.",
    "Su depósito de Bs. 1,000 fue acreditado en su cuenta BNB. Gracias por su confianza.",
    # Yape
    "Yape: Recibiste Bs. 50 de Juan Mamani. ¡Ya está disponible en tu cuenta!",
    "Yape: Enviaste Bs. 120 a María López. Código de operación: YP2024-5678.",
    "Yape te informa: Ahora puedes pagar en más de 50,000 comercios en Bolivia.",
    # Tigo Money
    "Tigo Money: Tu recarga de Bs. 30 fue procesada. Saldo actual: Bs. 95.50.",
    "Tigo Money: Transferencia de Bs. 200 recibida de Carlos Quispe. ¡Listo para usar!",
    "Tigo informa: Disfruta de internet ilimitado por 24hs activando tu paquete DailyMax.",
    # GAMLP
    "GAMLP informa: El trámite de Certificado de Uso de Suelo ref. GAMLP-2024-089 está en proceso.",
    "Municipio de La Paz: Pago de impuesto predial registrado correctamente. Recibo N° 00123456.",
    "GAMLP: Recuerde que el horario de atención en Subalcaldías es de 8:00 a 12:00 y de 14:30 a 18:30.",
    "La Paz Municipio: Su solicitud de inspección fue agendada para el martes 20 a las 10:00 AM.",
    # Impuestos Nacionales / SIN
    "Impuestos Nacionales: Declaración Form 200 presentada. Número de orden: SIN-2024-45678.",
    "SIN Bolivia: Le recordamos vence plazo declaración IVA el 15 del presente mes.",
    "Su NIT ha sido actualizado exitosamente en el sistema del SIN. Conserve su número de trámite.",
    # Entel
    "Entel: Tu paquete de datos de 2GB fue activado. Vigencia: 7 días. Saldo disponible: 2.0 GB.",
    "Entel Bolivia: Factura de internet hogar del mes de octubre: Bs. 220. Vence el 20/10.",
    "Entel te informa: Cobertura 4G ampliada a nuevas zonas de La Paz. Disfruta mayor velocidad.",
    # SEGIP
    "SEGIP: Su carnet de identidad N° 8734521 está listo para su recojo en la oficina central.",
    "Su trámite SEGIP ref. 2024-LP-00891 ha sido procesado. Pase a recoger en 3 días hábiles.",
    "SEGIP informa: Horario extendido viernes y sábados de 8:00 a 14:00 para renovaciones.",
    # Comercio legítimo
    "Mercado Libre Bolivia: Tu pedido #ML-2024-78901 fue enviado. Llegará en 3-5 días hábiles.",
    "Tu reserva en Hotel Europa La Paz fue confirmada. Check-in: 15 Nov, Check-out: 17 Nov.",
    "OLX Bolivia: Tu anuncio de venta fue publicado exitosamente. Ref: OLX-LP-45678.",
    # Generales
    "Recuerde que mañana es feriado por el Día de Todos Santos. No habrá atención en sucursales.",
    "Su contraseña fue cambiada exitosamente. Si no fue usted, contacte al 800-10-1234.",
    "Verificación de dos pasos activada en su cuenta. Código: 847291. Válido por 5 minutos.",
    "Resumen mensual: 12 transacciones realizadas por un total de Bs. 3,245. Banco Unión.",
    "Su solicitud de extracto bancario está siendo procesada. Recibirá el documento en 48 horas.",
    "Informe: La oficina de La Paz Centro atenderá con horario especial el próximo lunes.",
    "Gracias por usar nuestros servicios. Califique su atención en la app oficial.",
    "Entel: Hemos detectado que tu equipo soporta VoLTE. Actívalo gratis llamando al *5555.",
    "BNB informa: Su token digital fue renovado exitosamente. Vigencia: 12 meses.",
    "Banco Unión: Pago de servicio de luz ENDE procesado correctamente. Monto: Bs. 85.00.",
    "Tigo Bolivia: Su factura de internet del mes está disponible en Mi Tigo. Monto: Bs. 199.",
    "GAMLP: Le informamos que el plazo para actualizar su catastro vence el 30/11/2024.",
    "Su sesión en Banca en Línea Banco Unión se cerrará en 5 minutos por inactividad.",
    "Yape: Tu código de verificación es 391847. No lo compartas con nadie.",
    "Entel Bolivia: Recuerde que su contrato de servicio se renueva automáticamente el 01/12.",
]

PHISHING_MESSAGES = [
    # Phishing bancario boliviano
    "URGENTE - Banco Unión: Su cuenta ha sido BLOQUEADA por actividad sospechosa. Verifique sus datos AHORA en: http://bancounion-seguro.com/verificar o su cuenta será eliminada en 24 horas.",
    "BNB ALERTA: Detectamos acceso no autorizado a su cuenta. VERIFIQUE su identidad en http://bnb-bo-seguro.net/login antes de las 18:00 hs de hoy. URGENTE.",
    "Estimado cliente Banco Mercantil: Su tarjeta terminada en 4521 fue BLOQUEADA. Actualice datos en http://bmsc-actualizar.com para reactivarla. Responda a este mensaje con su NIT y contraseña.",
    "Su cuenta YAPE ha sido SUSPENDIDA. Para reactivarla ingrese a http://yape-bo-verificar.tk ahora mismo y confirme su PIN y número de CI.",
    "TIGO MONEY: Su transferencia de Bs. 2,000 fue RETENIDA por seguridad. Confirme su identidad en http://tigomoney-confirmar.ml o se cancelará definitivamente.",
    # Smishing de bonos y premios
    "MINISTERIO DE ECONOMÍA BOLIVIA: Usted fue SELECCIONADO para recibir el Bono Extraordinario de Bs. 2,000. Reclame ANTES de las 23:59 en http://bono-gobierno-bo.com con su CI y número de cuenta.",
    "GANASTE! El Gobierno de Bolivia te otorga Bs. 1,500 de Bono COVID. Para cobrar envíe su CI, número de cuenta Banco Unión y PIN a este número. No comparta este mensaje.",
    "ALCALDÍA LA PAZ: Tiene una multa de tránsito PENDIENTE de Bs. 850. Evite recargos pagando HOY en http://gamlp-multas.net. Con su CI y número de tarjeta.",
    "IMPUESTOS NACIONALES: Detectamos una DEUDA PENDIENTE en su NIT. Regularice AHORA en http://sin-bolivia-urgente.com o será sancionado con el 200% de recargo.",
    "SEGIP BOLIVIA: Su carnet de identidad ha VENCIDO y su CI fue ANULADO. Renuévelo urgente en http://segip-renovar.tk enviando foto de su CI actual y selfie.",
    # Smishing de telecomunicaciones
    "ENTEL BOLIVIA: Felicitaciones! Fue seleccionado para recibir 10GB de internet GRATIS por 1 año. Confirme sus datos en http://entel-premio.ml antes de medianoche.",
    "TIGO: Tienes acumulados 5,000 puntos de fidelidad que VENCEN HOY. Canjéalos en http://tigo-bo-canje.tk ingresando tu número y contraseña de Mi Tigo.",
    "VIVA BOLIVIA: Su recarga GRATIS de Bs. 50 está lista para activar. Haga clic en http://viva-bo-recarga.ml y confirme su número y NIP.",
    # Phishing de redes sociales / cuentas
    "FACEBOOK SEGURIDAD: Alguien intentó acceder a tu cuenta desde La Paz. Verifica AHORA tu identidad en http://fb-seguro-bo.com/verificar con usuario y contraseña o tu cuenta será eliminada.",
    "WHATSAPP: Su cuenta será DESACTIVADA en 12 horas por violación de términos. Verifique en http://whatsapp-bo-verificar.com o perderá todos sus mensajes.",
    # Phishing sofisticado con contexto boliviano
    "Estimado Sr./Sra., el Banco Unión le informa que por disposición de la ASFI (Autoridad de Supervisión del Sistema Financiero), TODOS los clientes deben actualizar sus datos antes del 30/11. Ingrese a http://bancounion-asfi-actualizacion.com",
    "BNB COMUNICADO: Por Resolución BCB-2024-089, su cuenta requiere verificación biométrica. Envíe foto de su carnet (ambos lados) y selfie sosteniendo el carnet a este WhatsApp. Proceso obligatorio.",
    "Yape Bolivia: Por mantenimiento del sistema, su cuenta Yape ha sido DESVINCULADA de su número. Para reactivar ingrese a http://yape-reactivar-bo.ml con sus credenciales bancarias.",
    "Su paquete del exterior fue retenido en ADUANAS BOLIVIA. Pague el arancel de Bs. 150 en 24hs en http://aduana-bo-pago.com o será devuelto. Tracking: BOL2024-98765.",
    "GAMLP MUNICIPAL: Su propiedad en La Paz tiene impuestos IMPAGAS desde 2022. Para evitar embargo judicial pague HOY en http://municipio-lapaz-cobros.com con tarjeta o QR.",
    # Mensajes con solicitud directa de credenciales
    "Hola, soy del área de seguridad del Banco Unión. Detectamos movimientos inusuales en su cuenta. Para protegerla necesitamos que nos confirme: número de cuenta, contraseña y el código que le llegará por SMS. Es urgente.",
    "Estimado cliente BNB: Para completar la actualización de su token digital envíe por favor su: 1) Número de cuenta, 2) Clave de 6 dígitos, 3) Número de CI. Esto es REQUERIDO por normativa ASFI.",
    "ALERTA TIGO MONEY: Para desbloquear las transferencias en su cuenta necesitamos verificar su identidad. Responda con: NIT, número de CI y PIN de Tigo Money. Tiene 30 minutos.",
    # Smishing con links acortados
    "BANCO UNIÓN: Recibió Bs. 5,000 de devolución de impuestos. Para acreditarlo en su cuenta haga clic: http://bit.ly/banco-union-devo y confirme sus datos.",
    "Yape te premia! Bs. 200 esperan por ti. Reclama en: http://tinyurl.com/yape-premio-bo antes de las 24hs.",
    "ENTEL: Plan ilimitado por Bs. 1 primer mes. Regístrate: http://bit.ly/entel-promo-bo ahora mismo.",
    # Más variantes
    "NOTA: Su cuenta bancaria recibirá una transferencia de Bs. 10,000 del gobierno. Para confirmar envíe su número de cuenta, banco y contraseña a este mensaje.",
    "Alerta de seguridad Banco Unión: Se registró un inicio de sesión desde IP extranjera. Bloquee accesos en http://bancounion.com-seguridad.net/bloquear con sus credenciales.",
    "Premio: Por ser cliente preferencial del BNB, ganó un viaje a Brasil. Para reclamar pague el impuesto de Bs. 300 en http://bnb-premio-viaje.com con su tarjeta.",
    "MINISTERIO SALUD BOLIVIA: Tiene vacuna COVID pendiente. Regístrese URGENTE en http://salud-bo-vacuna.tk con CI, teléfono y dirección para agendar cita.",
    "Su deuda con DELAPAZ por consumo de agua del periodo Enero-Junio 2024 asciende a Bs. 450. Pague hoy en http://delapaz-cobros.ml o se suspenderá el servicio.",
    # Phishing emocional
    "Mamá/Papá, estoy en problemas. Me robaron el celular y necesito Bs. 500 urgente. Por favor transfiérelos a esta cuenta Banco Unión: 1234567890. Te llamo después.",
    "SOY DE LA POLICÍA BOLIVIANA. Su familiar fue detenido. Para liberarlo sin cargos deposite fianza de Bs. 2,000 a la cuenta 0987654321 BNB. Llame al +1-555-FAKE.",
    "CONCURSO OFICIAL ENTEL 2024: Por usar datos móviles ganó un iPhone 15 Pro. Reclame en http://entel-iphone-bo.com pagando envío de Bs. 50 con su tarjeta.",
    "Estimado cliente: Por resolución judicial su cuenta Banco Unión será EMBARGADA en 48 horas si no regulariza su situación. Contáctenos en: http://bancounion-judicial.tk",
    "ALERTA BCB: El Banco Central de Bolivia detectó transacciones irregulares ligadas a su CI. Preséntese URGENTE o responda este mensaje con sus datos para verificación remota.",
]

assert len(LEGITIMATE_MESSAGES) >= 30, f"Se necesitan al menos 30 mensajes legítimos (hay {len(LEGITIMATE_MESSAGES)})"
assert len(PHISHING_MESSAGES) >= 30, f"Se necesitan al menos 30 mensajes de phishing (hay {len(PHISHING_MESSAGES)})"


def print_separator(title: str):
    width = 60
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def train_url_model():
    """Entrena el modelo de clasificación de URLs (RandomForestClassifier)."""
    print_separator("ENTRENAMIENTO: MODELO DE URLs")

    # Construir features
    print("  Extrayendo características de URLs...")
    X_legit = [extract_url_features(url) for url in LEGITIMATE_URLS]
    X_phish = [extract_url_features(url) for url in PHISHING_URLS]

    X = np.array(X_legit + X_phish)
    y = np.array([0] * len(LEGITIMATE_URLS) + [1] * len(PHISHING_URLS))

    # Aumentar dataset con variaciones
    extra_X, extra_y = [], []
    rng = np.random.RandomState(42)
    for i in range(len(X)):
        noise = rng.normal(0, 0.05, X[i].shape)
        extra_X.append(np.clip(X[i] + noise, 0, None))
        extra_y.append(y[i])
    for i in range(len(X)):
        noise = rng.normal(0, 0.08, X[i].shape)
        extra_X.append(np.clip(X[i] + noise, 0, None))
        extra_y.append(y[i])

    X_all = np.vstack([X, np.array(extra_X)])
    y_all = np.concatenate([y, np.array(extra_y)])

    print(f"  Dataset total de URLs: {len(X_all)} muestras ({(y_all==0).sum()} legítimas, {(y_all==1).sum()} phishing)")

    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n  📊 MÉTRICAS DEL MODELO DE URLs:")
    print(f"     Accuracy  : {accuracy_score(y_test, y_pred):.4f}")
    print(f"     Precision : {precision_score(y_test, y_pred):.4f}")
    print(f"     Recall    : {recall_score(y_test, y_pred):.4f}")
    print(f"     F1-Score  : {f1_score(y_test, y_pred):.4f}")
    print("\n  Reporte detallado:")
    print(classification_report(y_test, y_pred, target_names=["Legítimo", "Phishing"]))
    print("  Matriz de confusión:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    [[TN={cm[0,0]}  FP={cm[0,1]}]")
    print(f"     [FN={cm[1,0]}  TP={cm[1,1]}]]")

    # Feature importance
    feature_names = [
        "URL Length", "Hostname Length", "Shannon Entropy", "Subdomains",
        "Hyphens", "Digits", "@Count", "?Count", "=Count", "%Count",
        "Is IP", "HTTPS", "Levenshtein Dist", "Path Length", "Dot Count"
    ]
    importances = model.feature_importances_
    top_features = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:5]
    print("\n  🔍 Top 5 características más importantes:")
    for name, imp in top_features:
        bar = "█" * int(imp * 50)
        print(f"     {name:<20} {imp:.4f} {bar}")

    # Guardar modelo
    model_path = os.path.join(MODELS_DIR, "url_model.pkl")
    joblib.dump(model, model_path)
    print(f"\n  ✅ Modelo guardado en: {model_path}")
    return model


def train_message_model():
    """Entrena el modelo de clasificación de mensajes (TF-IDF + LogisticRegression)."""
    print_separator("ENTRENAMIENTO: MODELO DE MENSAJES")

    texts = LEGITIMATE_MESSAGES + PHISHING_MESSAGES
    labels = [0] * len(LEGITIMATE_MESSAGES) + [1] * len(PHISHING_MESSAGES)

    # Aumentar con variaciones simples
    augmented_texts, augmented_labels = [], []
    for text, label in zip(texts, labels):
        # Variante mayúsculas
        augmented_texts.append(text.upper())
        augmented_labels.append(label)
        # Variante con espacios extra
        augmented_texts.append(" " + text + " ")
        augmented_labels.append(label)

    all_texts = texts + augmented_texts
    all_labels = labels + augmented_labels

    print(f"  Dataset total de mensajes: {len(all_texts)} muestras ({all_labels.count(0)} legítimos, {all_labels.count(1)} phishing)")

    X_train, X_test, y_train, y_test = train_test_split(
        all_texts, all_labels, test_size=0.2, random_state=42, stratify=all_labels
    )

    # Pipeline: TF-IDF + LogisticRegression
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 3),
            max_features=8000,
            min_df=1,
            sublinear_tf=True,
            strip_accents="unicode",
            lowercase=True
        )),
        ("clf", LogisticRegression(
            C=1.5,
            class_weight="balanced",
            max_iter=1000,
            solver="lbfgs",
            random_state=42
        ))
    ])

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print("\n  📊 MÉTRICAS DEL MODELO DE MENSAJES:")
    print(f"     Accuracy  : {accuracy_score(y_test, y_pred):.4f}")
    print(f"     Precision : {precision_score(y_test, y_pred):.4f}")
    print(f"     Recall    : {recall_score(y_test, y_pred):.4f}")
    print(f"     F1-Score  : {f1_score(y_test, y_pred):.4f}")
    print("\n  Reporte detallado:")
    print(classification_report(y_test, y_pred, target_names=["Legítimo", "Phishing/Smishing"]))
    print("  Matriz de confusión:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    [[TN={cm[0,0]}  FP={cm[0,1]}]")
    print(f"     [FN={cm[1,0]}  TP={cm[1,1]}]]")

    # Términos más importantes
    tfidf = pipeline.named_steps["tfidf"]
    clf = pipeline.named_steps["clf"]
    feature_names = tfidf.get_feature_names_out()
    coefs = clf.coef_[0]
    top_phishing_terms = [(feature_names[i], coefs[i]) for i in coefs.argsort()[-10:][::-1]]
    print("\n  🔍 Top 10 términos indicadores de PHISHING:")
    for term, coef in top_phishing_terms:
        bar = "█" * int(abs(coef) * 5)
        print(f"     '{term}'  ({coef:+.3f}) {bar}")

    # Guardar modelo (pipeline completo)
    model_path = os.path.join(MODELS_DIR, "message_model.pkl")
    joblib.dump(pipeline, model_path)
    print(f"\n  ✅ Pipeline guardado en: {model_path}")
    return pipeline


def save_dataset_info():
    """Guarda información del dataset para referencia."""
    info = {
        "url_dataset": {
            "legitimate": len(LEGITIMATE_URLS),
            "phishing": len(PHISHING_URLS),
            "total": len(LEGITIMATE_URLS) + len(PHISHING_URLS)
        },
        "message_dataset": {
            "legitimate": len(LEGITIMATE_MESSAGES),
            "phishing": len(PHISHING_MESSAGES),
            "total": len(LEGITIMATE_MESSAGES) + len(PHISHING_MESSAGES)
        },
        "context": "Bolivia - La Paz: Banco Unión, BNB, BMSC, Yape, Tigo Money, GAMLP, SIN, SEGIP, Entel, DeLaPaz"
    }
    with open(os.path.join(MODELS_DIR, "dataset_info.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)
    print(f"\n  📄 Info del dataset guardada en: {os.path.join(MODELS_DIR, 'dataset_info.json')}")


if __name__ == "__main__":
    print("\n" + "🛡️ " * 10)
    print("  ESCUDO DIGITAL LA PAZ — Entrenamiento de Modelos de IA")
    print("  Sistema Anti-Phishing Contextualizado a Bolivia")
    print("🛡️ " * 10)

    url_model = train_url_model()
    msg_model = train_message_model()
    save_dataset_info()

    print_separator("ENTRENAMIENTO COMPLETADO")
    print("  ✅ Modelos guardados en carpeta 'models/'")
    print("  ✅ url_model.pkl  — RandomForestClassifier (15 características)")
    print("  ✅ message_model.pkl — TF-IDF + LogisticRegression Pipeline")
    print("  ℹ️  Ahora ejecute: python app.py")
    print("=" * 60 + "\n")
