CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS scenarios (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(128) UNIQUE NOT NULL,
    name VARCHAR(256) NOT NULL,
    description TEXT,
    category VARCHAR(64) NOT NULL DEFAULT 'generic',
    attck_technique VARCHAR(32),
    attck_tactic VARCHAR(64),
    severity VARCHAR(16) NOT NULL DEFAULT 'medium',
    expected_rule_key VARCHAR(128),
    expected_alert_type VARCHAR(128),
    is_negative_control BOOLEAN NOT NULL DEFAULT FALSE,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(128) UNIQUE NOT NULL,
    title VARCHAR(256) NOT NULL,
    description TEXT,
    format VARCHAR(32) NOT NULL DEFAULT 'sigma',
    content TEXT NOT NULL,
    level VARCHAR(16) NOT NULL DEFAULT 'medium',
    logsource JSONB NOT NULL DEFAULT '{}'::jsonb,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scenario_id UUID NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
    run_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    outcome VARCHAR(32),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    detection_latency_ms DOUBLE PRECISION,
    telemetry_available BOOLEAN NOT NULL DEFAULT FALSE,
    matched_rule_keys JSONB NOT NULL DEFAULT '[]'::jsonb,
    error_message TEXT,
    context JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS ix_executions_run_id ON executions(run_id);
CREATE INDEX IF NOT EXISTS ix_executions_started_at ON executions(started_at DESC);

CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    kind VARCHAR(32) NOT NULL,
    source VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw TEXT,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    rule_key VARCHAR(128),
    title VARCHAR(256) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'medium',
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    latency_ms DOUBLE PRECISION,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS coverage_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    taken_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detection_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
    telemetry_availability DOUBLE PRECISION NOT NULL DEFAULT 0,
    rule_match_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
    false_positive_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
    avg_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
    reliability_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    attck_coverage JSONB NOT NULL DEFAULT '{}'::jsonb,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS ix_coverage_snapshots_taken_at ON coverage_snapshots(taken_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(64) NOT NULL DEFAULT 'system',
    action VARCHAR(64) NOT NULL,
    target VARCHAR(256),
    status VARCHAR(16) NOT NULL DEFAULT 'ok',
    detail JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp ON audit_logs(timestamp DESC);