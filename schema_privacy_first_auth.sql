-- ============================================================================
-- Privacy-First Authentication & Identity Isolation Schema
-- Architectural Reference for Problem 4.1: Mitigating PII Exposure
-- ============================================================================
-- Standards: GDPR (Art. 5, 17, 25 Privacy by Design), OIDC PPID, NIST SP 800-63B
-- Target Dialect: PostgreSQL / SQLite Compatible ANSI SQL DDL
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Core Identity Vault (Zero-Knowledge / Blinded Reference)
-- ----------------------------------------------------------------------------
-- The primary identity store decouples authentication from plain email storage.
-- Email addresses are blinded using HMAC-SHA256 with an HSM/KMS-managed pepper.

CREATE TABLE core_identity_accounts (
    account_uuid VARCHAR(36) PRIMARY KEY,
    
    -- Blinded identifier for duplicate detection & abuse prevention
    -- Computed as: HMAC_SHA256(kms_pepper, lowercase(trim(email)) || account_salt)
    blinded_email_hash CHAR(64) NOT NULL UNIQUE,
    account_salt CHAR(32) NOT NULL,

    -- Hardware-backed WebAuthn / Passkey credential public key reference
    -- Eliminates the reliance on email-based password recovery
    primary_auth_method VARCHAR(20) NOT NULL DEFAULT 'WEBAUTHN' 
        CHECK (primary_auth_method IN ('WEBAUTHN', 'FIDO2_PASSKEY', 'MASKED_OIDC')),

    account_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (account_status IN ('ACTIVE', 'SUSPENDED', 'PENDING_DELETION', 'ERASED')),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_authenticated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_blinded_email_lookup ON core_identity_accounts(blinded_email_hash);


-- ----------------------------------------------------------------------------
-- 2. Pairwise Pseudonymous Identifier (PPID) Mapping
-- ----------------------------------------------------------------------------
-- When a user interacts with different internal subsystems, partner services, 
-- or client apps, each client is issued a distinct PPID.
-- Even if client A and client B collude, their user IDs cannot be linked.

CREATE TABLE client_applications (
    client_id VARCHAR(64) PRIMARY KEY,
    client_name VARCHAR(255) NOT NULL,
    organization_id VARCHAR(64) NOT NULL,
    trust_tier VARCHAR(20) NOT NULL DEFAULT 'UNTRUSTED'
        CHECK (trust_tier IN ('INTERNAL', 'VERIFIED_PARTNER', 'UNTRUSTED', 'EPHEMERAL')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE pairwise_pseudonymous_identifiers (
    ppid_uuid VARCHAR(36) PRIMARY KEY,
    account_uuid VARCHAR(36) NOT NULL,
    client_id VARCHAR(64) NOT NULL,

    -- Pseudonymous ID presented exclusively to this client
    -- PPID = HMAC_SHA256(account_uuid, client_id || client_salt)
    client_facing_pseudonym CHAR(64) NOT NULL UNIQUE,
    client_salt CHAR(32) NOT NULL,

    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,

    FOREIGN KEY (account_uuid) REFERENCES core_identity_accounts(account_uuid) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES client_applications(client_id) ON DELETE CASCADE,
    UNIQUE (account_uuid, client_id)
);

CREATE INDEX idx_ppid_lookup ON pairwise_pseudonymous_identifiers(client_facing_pseudonym);


-- ----------------------------------------------------------------------------
-- 3. Dynamic Masked Relays & Granular Kill-Switches
-- ----------------------------------------------------------------------------
-- Per-service routing table allowing users to receive service messages through
-- cryptographically masked addresses while maintaining full leak attribution.

CREATE TABLE masked_email_relays (
    relay_id VARCHAR(36) PRIMARY KEY,
    account_uuid VARCHAR(36) NOT NULL,
    client_id VARCHAR(64) NOT NULL,

    -- Unique per-service alias: e.g. service-slug.x9f82@relay.domain.com
    alias_address VARCHAR(255) NOT NULL UNIQUE,
    expected_sender_domain VARCHAR(255) NOT NULL,

    -- Encrypted canonical forward destination (AES-256-GCM envelope encryption)
    encrypted_destination_envelope TEXT NOT NULL,

    -- Auto-expiration & lifecycle policies
    retention_tier VARCHAR(20) NOT NULL DEFAULT 'COMMERCIAL'
        CHECK (retention_tier IN ('CORE', 'COMMERCIAL', 'EPHEMERAL_TRIAL', 'ONE_TIME')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Granular Kill-Switch
    forwarding_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    kill_switch_triggered_at TIMESTAMP WITH TIME ZONE,
    kill_switch_reason VARCHAR(100),

    FOREIGN KEY (account_uuid) REFERENCES core_identity_accounts(account_uuid) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES client_applications(client_id) ON DELETE CASCADE
);

CREATE INDEX idx_alias_routing ON masked_email_relays(alias_address);


-- ----------------------------------------------------------------------------
-- 4. Automated Retention & GDPR Art. 17 Erasure Compliance
-- ----------------------------------------------------------------------------
-- Enforces storage limitation (GDPR Art. 5(1)(e)) with scheduled automated purges.

CREATE TABLE data_retention_schedules (
    schedule_id VARCHAR(36) PRIMARY KEY,
    account_uuid VARCHAR(36) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    data_category VARCHAR(50) NOT NULL,  -- 'REGISTRATION_METADATA', 'TRIAL_LOGS', 'MARKETING_OPT_IN'

    scheduled_purge_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    purge_status VARCHAR(20) NOT NULL DEFAULT 'SCHEDULED'
        CHECK (purge_status IN ('SCHEDULED', 'PURGED', 'EXEMPT_LEGAL_HOLD')),

    purged_at TIMESTAMP WITH TIME ZONE,
    erasure_verification_receipt CHAR(64), -- SHA-256 receipt proving hard deletion to data subject

    FOREIGN KEY (account_uuid) REFERENCES core_identity_accounts(account_uuid) ON DELETE CASCADE
);

CREATE INDEX idx_pending_purges ON data_retention_schedules(scheduled_purge_timestamp, purge_status);


-- ----------------------------------------------------------------------------
-- 5. Immutable Consent Ledger (GDPR Art. 7 & CCPA Audit Trail)
-- ----------------------------------------------------------------------------
CREATE TABLE consent_audit_ledger (
    ledger_entry_id BIGSERIAL PRIMARY KEY,
    account_uuid VARCHAR(36) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    consent_purpose VARCHAR(100) NOT NULL,
    consent_state VARCHAR(20) NOT NULL CHECK (consent_state IN ('GRANTED', 'WITHDRAWN', 'EXPIRED')),
    ip_subnet_hash CHAR(64) NOT NULL, -- Anonymized IP hash
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (account_uuid) REFERENCES core_identity_accounts(account_uuid) ON DELETE CASCADE
);
