-- AUD initial schema. Runs as aud_owner, which becomes the owner of every object.
-- Roles aud_owner and aud_app are created by deploy/initdb (passwords come from .env).

-- Emitting modules of MediNet-Core. Read-only reference data.
CREATE TABLE source_modules (
    code VARCHAR(3) PRIMARY KEY CHECK (code ~ '^[A-Z]{3}$'),
    name TEXT       NOT NULL
);

INSERT INTO source_modules (code, name) VALUES
    ('IAM', 'Autenticación y Gestión de Identidades'),
    ('PAC', 'Gestión de Pacientes y Admisión'),
    ('MED', 'Gestión de Personal Clínico y Médicos'),
    ('AGT', 'Agenda y Citaciones'),
    ('HCE', 'Historia Clínica Electrónica'),
    ('PAB', 'Pabellones y Quirófanos'),
    ('LAB', 'Laboratorio Clínico y Exámenes'),
    ('FAR', 'Farmacia e Insumos'),
    ('TRG', 'Urgencias y Triage'),
    ('FAC', 'Facturación y Convenios'),
    ('AUD', 'Auditoría y Trazabilidad de Seguridad'),
    ('TEL', 'Portal del Paciente y Telemedicina');

-- Clients allowed to ingest events, one or more per module.
CREATE TABLE api_clients (
    client_id   VARCHAR(64) PRIMARY KEY CHECK (client_id ~ '^[a-z0-9][a-z0-9_-]{2,63}$'),
    module_code VARCHAR(3)  NOT NULL REFERENCES source_modules (code),
    -- HMAC secret encrypted with AES-256-GCM (nonce || ciphertext || tag).
    -- It cannot be hashed: verifying an HMAC signature needs the original secret.
    -- The encryption key lives outside the database (.env).
    secret_enc  BYTEA       NOT NULL,
    active      BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (client_id, module_code)
);

-- Append-only security event log.
CREATE TABLE audit_logs (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id        UUID         NOT NULL UNIQUE,
    client_id       VARCHAR(64)  NOT NULL,
    source_module   VARCHAR(3)   NOT NULL,
    event_type      VARCHAR(64)  NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    -- 0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    severity        SMALLINT     NOT NULL CHECK (severity BETWEEN 0 AND 4),
    actor_id        VARCHAR(128),
    actor_type      VARCHAR(32),
    target_resource VARCHAR(256),
    source_ip       INET,
    user_agent      VARCHAR(512),
    occurred_at     TIMESTAMPTZ  NOT NULL,
    received_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    payload         JSONB        NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    -- Hash chain: hash = SHA256(prev_hash || canonical event). The first row uses 32 zero bytes as prev_hash.
    -- UNIQUE (prev_hash) forbids forks: every hash can be extended only once.
    prev_hash       BYTEA        NOT NULL UNIQUE CHECK (octet_length(prev_hash) = 32),
    hash            BYTEA        NOT NULL UNIQUE CHECK (octet_length(hash) = 32),
    -- A client can only emit events for its own module.
    FOREIGN KEY (client_id, source_module) REFERENCES api_clients (client_id, module_code)
);

-- Keyset pagination cursor (occurred_at, id) and the query filters.
CREATE INDEX audit_logs_occurred_at_idx   ON audit_logs (occurred_at DESC, id DESC);
CREATE INDEX audit_logs_event_type_idx    ON audit_logs (event_type, occurred_at);
CREATE INDEX audit_logs_severity_idx      ON audit_logs (severity, occurred_at);
CREATE INDEX audit_logs_actor_id_idx      ON audit_logs (actor_id, occurred_at);
CREATE INDEX audit_logs_source_module_idx ON audit_logs (source_module, occurred_at);

-- Second immutability layer: rejects changes even from roles that hold the privilege.
CREATE FUNCTION audit_logs_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % is not allowed', TG_OP;
END;
$$;

CREATE TRIGGER audit_logs_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation();

CREATE TRIGGER audit_logs_no_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_reject_mutation();

-- First immutability layer: the runtime role can only insert and read.
REVOKE ALL ON source_modules, api_clients, audit_logs FROM PUBLIC;
GRANT SELECT ON source_modules, api_clients TO aud_app;
GRANT SELECT, INSERT ON audit_logs TO aud_app;
