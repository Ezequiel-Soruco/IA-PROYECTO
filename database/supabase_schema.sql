-- Esquema DDL para Supabase (PostgreSQL)
-- Escudo Digital La Paz - Monitoreo Georreferenciado de Amenazas

CREATE TABLE IF NOT EXISTS bolivian_whitelist (
    id BIGSERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    entity_name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL, -- 'Banca', 'Gobierno', 'Telecomunicaciones', 'Universidad'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_reports (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    input_type VARCHAR(50) NOT NULL, -- 'url', 'message', 'image'
    target_url TEXT,
    message_content TEXT,
    risk_score NUMERIC(5,2) NOT NULL,
    verdict VARCHAR(50) NOT NULL, -- 'SEGURO', 'SOSPECHOSO', 'PELIGROSO (PHISHING)'
    entity_targeted VARCHAR(100), -- 'Banco Unión', 'Yape', 'GAMLP', etc.
    attack_type VARCHAR(100), -- 'Robo de Credenciales', 'Falso Bono', 'Estafa QR'
    macrodistrito VARCHAR(150), -- Macrodistrito de La Paz reportado
    factors JSONB, -- Desglose explicable de ciberseguridad
    whois_age_days INTEGER,
    ssl_issuer VARCHAR(255),
    ip_hash VARCHAR(64) -- Anonimizado
);

-- Índices para optimizar dashboard en tiempo real
CREATE INDEX IF NOT EXISTS idx_threat_reports_macrodistrito ON threat_reports(macrodistrito);
CREATE INDEX IF NOT EXISTS idx_threat_reports_verdict ON threat_reports(verdict);
CREATE INDEX IF NOT EXISTS idx_threat_reports_created_at ON threat_reports(created_at DESC);
