CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,

    email TEXT NOT NULL UNIQUE,
    display_name TEXT,

    password_hash TEXT,

    role TEXT NOT NULL DEFAULT 'user',

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    valid_from TEXT,
    account_expires_at TEXT,

    email_verified_at TEXT,
    email_verification_token TEXT,

    password_reset_token TEXT,
    password_reset_sent_at TEXT,

    last_login_at TEXT,
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    preferred_language TEXT DEFAULT NULL,
    receive_application_emails BOOLEAN NOT NULL DEFAULT FALSE,

    public_slug TEXT DEFAULT NULL,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS public_slug TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS can_use_local_space BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ui_theme TEXT DEFAULT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_slug
ON users(public_slug) WHERE public_slug IS NOT NULL;

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    source_type TEXT NOT NULL,
    source_value TEXT NOT NULL,

    source_hash TEXT,

    status TEXT NOT NULL DEFAULT 'created',

    provider_config_id TEXT,
    provider_name TEXT,
    provider_profile_name TEXT,
    provider_resource_id TEXT,
    provider_status TEXT,
    provider_payload_json TEXT,

    destination_config_id TEXT,
    destination_name TEXT,
    destination_profile_name TEXT,

    output_mode TEXT,
    output_links_json TEXT,
    unrestricted_at TEXT,

    error_message TEXT,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    started_at TEXT,
    completed_at TEXT,
    cancelled_at TEXT,

    send_to_destination BOOLEAN NOT NULL DEFAULT FALSE,
    sent_to_destination BOOLEAN NOT NULL DEFAULT FALSE,
    sent_to_destination_at TEXT,

    destination_status TEXT,
    destination_message TEXT,
    destination_message_key TEXT,
    destination_message_params TEXT,
    destination_last_attempt TEXT,
    destination_path TEXT,
    destination_progress INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_jobs_user_id ON jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_jobs_user_status ON jobs(user_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_source_hash ON jobs(user_id, source_hash);
CREATE INDEX IF NOT EXISTS idx_jobs_provider_config_id ON jobs(user_id, provider_config_id);
CREATE INDEX IF NOT EXISTS idx_jobs_destination_config_id ON jobs(user_id, destination_config_id);

CREATE TABLE IF NOT EXISTS provider_configs (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    provider_type TEXT NOT NULL,
    name TEXT NOT NULL,

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,

    encrypted_api_key TEXT,

    account_expires_at TEXT,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_provider_configs_user_id ON provider_configs(user_id);
CREATE INDEX IF NOT EXISTS idx_provider_configs_user_type ON provider_configs(user_id, provider_type);
CREATE INDEX IF NOT EXISTS idx_provider_configs_user_default ON provider_configs(user_id, is_default);

CREATE TABLE IF NOT EXISTS destination_configs (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    destination_type TEXT NOT NULL,
    name TEXT NOT NULL,

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,

    config_json TEXT NOT NULL DEFAULT '{}',

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_destination_configs_user_id ON destination_configs(user_id);
CREATE INDEX IF NOT EXISTS idx_destination_configs_user_type ON destination_configs(user_id, destination_type);
CREATE INDEX IF NOT EXISTS idx_destination_configs_user_default ON destination_configs(user_id, is_default);

CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    token TEXT NOT NULL UNIQUE,

    label TEXT,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_api_keys (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL UNIQUE,

    scopes_json TEXT NOT NULL DEFAULT '[]',

    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at TEXT,

    last_used_at TEXT,
    last_used_ip TEXT,
    last_used_scope TEXT,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_user_api_keys_user_id
ON user_api_keys(user_id);

CREATE INDEX IF NOT EXISTS idx_user_api_keys_prefix
ON user_api_keys(key_prefix);

CREATE INDEX IF NOT EXISTS idx_user_api_keys_user_active
ON user_api_keys(user_id, is_active);

CREATE TABLE IF NOT EXISTS smtp_settings (
    id TEXT PRIMARY KEY,

    enabled BOOLEAN NOT NULL DEFAULT FALSE,

    host TEXT,
    port INTEGER NOT NULL DEFAULT 587,

    username TEXT,
    encrypted_password TEXT,

    from_email TEXT,
    from_name TEXT,

    use_tls BOOLEAN NOT NULL DEFAULT TRUE,
    use_ssl BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS account_tokens (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    token_hash TEXT NOT NULL UNIQUE,
    token_type TEXT NOT NULL,

    expires_at TEXT NOT NULL,
    used_at TEXT,

    created_at TEXT NOT NULL,
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,

    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_account_tokens_user_id ON account_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_account_tokens_type ON account_tokens(token_type);
CREATE INDEX IF NOT EXISTS idx_account_tokens_hash ON account_tokens(token_hash);

CREATE TABLE IF NOT EXISTS notification_configs (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    name TEXT NOT NULL,
    channel TEXT NOT NULL,

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,

    config_json TEXT NOT NULL DEFAULT '{}',

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_rules (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    name TEXT NOT NULL,

    scope TEXT NOT NULL DEFAULT 'user',

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    config_id TEXT NOT NULL REFERENCES notification_configs(id) ON DELETE CASCADE,

    severity_min TEXT NOT NULL DEFAULT 'info',
    event_types_json TEXT NOT NULL DEFAULT '[]',

    rate_limit_per_hour INTEGER NOT NULL DEFAULT 30,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_events (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    job_id TEXT,

    type TEXT NOT NULL,
    severity TEXT NOT NULL,

    title TEXT NOT NULL,
    message TEXT NOT NULL,

    payload_json TEXT NOT NULL DEFAULT '{}',

    status TEXT NOT NULL DEFAULT 'pending',

    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,

    last_error TEXT,

    triggered_by_rule_ids_json TEXT NOT NULL DEFAULT '[]',
    triggered_by_config_ids_json TEXT NOT NULL DEFAULT '[]',

    next_retry_at TEXT,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    sent_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_notification_configs_user_id
ON notification_configs(user_id);

CREATE INDEX IF NOT EXISTS idx_notification_configs_user_channel
ON notification_configs(user_id, channel);

CREATE INDEX IF NOT EXISTS idx_notification_configs_user_default
ON notification_configs(user_id, channel, is_default);

CREATE INDEX IF NOT EXISTS idx_notification_rules_user_id
ON notification_rules(user_id);

CREATE INDEX IF NOT EXISTS idx_notification_rules_config_id
ON notification_rules(config_id);

CREATE INDEX IF NOT EXISTS idx_notification_rules_user_enabled
ON notification_rules(user_id, is_enabled);

CREATE INDEX IF NOT EXISTS idx_notification_rules_user_scope
ON notification_rules(user_id, scope);

CREATE INDEX IF NOT EXISTS idx_notification_events_user_id
ON notification_events(user_id);

CREATE INDEX IF NOT EXISTS idx_notification_events_status
ON notification_events(status);

CREATE INDEX IF NOT EXISTS idx_notification_events_next_retry_at
ON notification_events(next_retry_at);

CREATE INDEX IF NOT EXISTS idx_notification_events_user_status
ON notification_events(user_id, status);

CREATE INDEX IF NOT EXISTS idx_notification_events_job_id
ON notification_events(job_id);


CREATE TABLE IF NOT EXISTS external_client_submissions (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    client_type TEXT NOT NULL,
    source TEXT NOT NULL,

    input_type TEXT NOT NULL,
    input_hash TEXT,
    original_name TEXT,
    category TEXT,

    provider_config_id TEXT,
    destination_config_id TEXT,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,

    status TEXT NOT NULL,
    error_message TEXT,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_external_client_submissions_user_id
ON external_client_submissions(user_id);

CREATE INDEX IF NOT EXISTS idx_external_client_submissions_user_created
ON external_client_submissions(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_external_client_submissions_job_id
ON external_client_submissions(job_id);

CREATE INDEX IF NOT EXISTS idx_external_client_submissions_input_hash
ON external_client_submissions(input_hash);

CREATE TABLE IF NOT EXISTS user_integration_settings (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

    prowlarr_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    prowlarr_url TEXT,
    prowlarr_open_mode TEXT NOT NULL DEFAULT 'both',
    home_page TEXT NOT NULL DEFAULT 'jobs',

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_integration_settings_user_id
ON user_integration_settings(user_id);

CREATE TABLE IF NOT EXISTS announcements (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'news',
    severity TEXT NOT NULL DEFAULT 'info',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    show_as_banner BOOLEAN NOT NULL DEFAULT FALSE,
    require_acknowledgement BOOLEAN NOT NULL DEFAULT FALSE,
    track_open BOOLEAN NOT NULL DEFAULT FALSE,
    send_email BOOLEAN NOT NULL DEFAULT FALSE,
    starts_at TEXT,
    ends_at TEXT,
    deleted_at TEXT,
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_announcements_active
ON announcements(is_active);

CREATE INDEX IF NOT EXISTS idx_announcements_window
ON announcements(is_active, starts_at, ends_at);

CREATE INDEX IF NOT EXISTS idx_announcements_deleted
ON announcements(deleted_at);

CREATE TABLE IF NOT EXISTS announcement_reads (
    id TEXT PRIMARY KEY,
    announcement_id TEXT NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    opened_at TEXT,
    read_at TEXT,
    acknowledged_at TEXT,
    email_sent_at TEXT,
    email_status TEXT,
    email_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (announcement_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_announcement_reads_ann_id
ON announcement_reads(announcement_id);

CREATE INDEX IF NOT EXISTS idx_announcement_reads_user_id
ON announcement_reads(user_id);

CREATE INDEX IF NOT EXISTS idx_announcement_reads_ann_user
ON announcement_reads(announcement_id, user_id);

CREATE TABLE IF NOT EXISTS email_templates (
    id TEXT PRIMARY KEY,
    template_key TEXT NOT NULL,
    language TEXT NOT NULL,
    subject_template TEXT NOT NULL,
    body_template TEXT NOT NULL,
    is_custom BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(template_key, language)
);

CREATE INDEX IF NOT EXISTS idx_email_templates_key_lang
ON email_templates(template_key, language);


CREATE TABLE IF NOT EXISTS external_identities (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    provider TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,

    email TEXT,

    linked_at TEXT NOT NULL,
    last_used_at TEXT,

    UNIQUE (issuer, subject)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_external_identities_issuer_subject
ON external_identities (issuer, subject);

CREATE INDEX IF NOT EXISTS idx_external_identities_user_id
ON external_identities (user_id);


CREATE TABLE IF NOT EXISTS oidc_states (
    id TEXT PRIMARY KEY,

    state TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL,

    exchange_code TEXT,
    user_id TEXT,

    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_states_state
ON oidc_states (state);

CREATE INDEX IF NOT EXISTS idx_oidc_states_exchange_code
ON oidc_states (exchange_code);

CREATE INDEX IF NOT EXISTS idx_oidc_states_expires_at
ON oidc_states (expires_at);

-- Migration: provider_id added for multi-provider OIDC (v3.6)
ALTER TABLE oidc_states ADD COLUMN IF NOT EXISTS provider_id TEXT DEFAULT NULL;


CREATE TABLE IF NOT EXISTS oidc_providers (
    id                        TEXT    PRIMARY KEY,
    name                      TEXT    NOT NULL,
    slug                      TEXT    NOT NULL UNIQUE,
    enabled                   BOOLEAN NOT NULL DEFAULT TRUE,
    issuer                    TEXT    NOT NULL UNIQUE,
    client_id                 TEXT    NOT NULL,
    encrypted_client_secret   TEXT,
    scopes                    TEXT    NOT NULL DEFAULT 'openid email profile',
    button_label              TEXT    NOT NULL,
    auto_create_users         BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_domains_json      TEXT    NOT NULL DEFAULT '[]',
    state_ttl_seconds         INTEGER NOT NULL DEFAULT 600,
    exchange_code_ttl_seconds INTEGER NOT NULL DEFAULT 60,
    sort_order                INTEGER NOT NULL DEFAULT 0,
    created_at                TEXT    NOT NULL,
    updated_at                TEXT    NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_providers_slug
ON oidc_providers (slug);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_providers_issuer
ON oidc_providers (issuer);

CREATE INDEX IF NOT EXISTS idx_oidc_providers_sort
ON oidc_providers (sort_order, created_at);


CREATE TABLE IF NOT EXISTS identity_proxy_configs (
    id                   TEXT    PRIMARY KEY,
    name                 TEXT    NOT NULL,
    provider_type        TEXT    NOT NULL,
    enabled              BOOLEAN NOT NULL DEFAULT FALSE,
    label                TEXT    NOT NULL,
    auto_login           BOOLEAN NOT NULL DEFAULT TRUE,
    auto_create_users    BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_domains_json TEXT    NOT NULL DEFAULT '[]',
    config_json          TEXT    NOT NULL DEFAULT '{}',
    created_at           TEXT    NOT NULL,
    updated_at           TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_proxy_configs_enabled
ON identity_proxy_configs (enabled, created_at);
