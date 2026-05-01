PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cloudflare_sync_owners (
    owner_uid TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    active_key_version INTEGER NOT NULL CHECK (active_key_version > 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    CHECK (length(owner_uid) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS cloudflare_sync_devices (
    owner_uid TEXT NOT NULL,
    device_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('desktop', 'phone', 'web-planner')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    platform TEXT NOT NULL,
    sync_scopes_json TEXT NOT NULL CHECK (json_valid(sync_scopes_json)),
    signing_public_key_json TEXT NOT NULL CHECK (json_valid(signing_public_key_json)),
    wrap_public_key_json TEXT NOT NULL CHECK (json_valid(wrap_public_key_json)),
    enrollment_epoch INTEGER NOT NULL CHECK (enrollment_epoch > 0),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    device_sequence INTEGER NOT NULL CHECK (device_sequence >= 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= 0),
    revoked_by_device_id TEXT,
    last_seen_at INTEGER CHECK (last_seen_at IS NULL OR last_seen_at >= 0),
    PRIMARY KEY (owner_uid, device_id),
    FOREIGN KEY (owner_uid) REFERENCES cloudflare_sync_owners(owner_uid) ON DELETE CASCADE,
    CHECK (device_id GLOB 'dev_*'),
    CHECK (revoked_at IS NULL OR status = 'revoked')
);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_devices_owner_status
    ON cloudflare_sync_devices(owner_uid, status, role);

CREATE TABLE IF NOT EXISTS cloudflare_sync_enrollment_requests (
    owner_uid TEXT NOT NULL,
    request_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('phone', 'web-planner')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'claimed', 'revoked', 'expired')),
    pairing_challenge_hash TEXT NOT NULL,
    device_json TEXT NOT NULL CHECK (json_valid(device_json)),
    requested_at INTEGER NOT NULL CHECK (requested_at >= 0),
    approved_at INTEGER CHECK (approved_at IS NULL OR approved_at >= 0),
    claimed_at INTEGER CHECK (claimed_at IS NULL OR claimed_at >= 0),
    approved_by_device_id TEXT,
    key_grant_id TEXT,
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
    PRIMARY KEY (owner_uid, request_id),
    FOREIGN KEY (owner_uid) REFERENCES cloudflare_sync_owners(owner_uid) ON DELETE CASCADE,
    FOREIGN KEY (owner_uid, device_id) REFERENCES cloudflare_sync_devices(owner_uid, device_id) ON DELETE CASCADE,
    CHECK (request_id GLOB 'dev_*'),
    CHECK (device_id GLOB 'dev_*'),
    CHECK (key_grant_id IS NULL OR key_grant_id GLOB 'grant_*')
);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_enrollments_pending
    ON cloudflare_sync_enrollment_requests(owner_uid, status, requested_at);

CREATE TABLE IF NOT EXISTS cloudflare_sync_key_grants (
    owner_uid TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    created_by_device_id TEXT NOT NULL,
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    wrap_alg TEXT NOT NULL CHECK (wrap_alg = 'RSA-OAEP-256'),
    wrapped_key_ciphertext TEXT NOT NULL,
    wrapped_key_hash TEXT NOT NULL,
    grant_json TEXT NOT NULL CHECK (json_valid(grant_json)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= 0),
    revoked_by_device_id TEXT,
    PRIMARY KEY (owner_uid, grant_id),
    FOREIGN KEY (owner_uid) REFERENCES cloudflare_sync_owners(owner_uid) ON DELETE CASCADE,
    FOREIGN KEY (owner_uid, recipient_device_id) REFERENCES cloudflare_sync_devices(owner_uid, device_id) ON DELETE CASCADE,
    FOREIGN KEY (owner_uid, created_by_device_id) REFERENCES cloudflare_sync_devices(owner_uid, device_id) ON DELETE CASCADE,
    CHECK (grant_id GLOB 'grant_*'),
    CHECK (recipient_device_id GLOB 'dev_*'),
    CHECK (created_by_device_id GLOB 'dev_*')
);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_key_grants_recipient
    ON cloudflare_sync_key_grants(owner_uid, recipient_device_id, key_version, revoked_at);

CREATE TABLE IF NOT EXISTS cloudflare_sync_snapshots (
    owner_uid TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_sequence INTEGER NOT NULL CHECK (device_sequence >= 0),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'tombstoned', 'conflict')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    received_at INTEGER NOT NULL CHECK (received_at >= 0),
    ciphertext_hash TEXT NOT NULL,
    envelope_json TEXT NOT NULL CHECK (json_valid(envelope_json)),
    PRIMARY KEY (owner_uid, revision_id),
    FOREIGN KEY (owner_uid) REFERENCES cloudflare_sync_owners(owner_uid) ON DELETE CASCADE,
    FOREIGN KEY (owner_uid, device_id) REFERENCES cloudflare_sync_devices(owner_uid, device_id) ON DELETE CASCADE,
    UNIQUE (owner_uid, device_id, device_sequence),
    CHECK (revision_id GLOB 'srev_*'),
    CHECK (snapshot_id GLOB 'snap_*')
);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_snapshots_latest
    ON cloudflare_sync_snapshots(owner_uid, status, received_at DESC);

CREATE TABLE IF NOT EXISTS cloudflare_sync_state (
    owner_uid TEXT PRIMARY KEY,
    latest_snapshot_revision_id TEXT,
    active_key_version INTEGER NOT NULL CHECK (active_key_version > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    FOREIGN KEY (owner_uid) REFERENCES cloudflare_sync_owners(owner_uid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cloudflare_sync_patches (
    owner_uid TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    patch_id TEXT NOT NULL,
    base_revision_id TEXT,
    device_id TEXT NOT NULL,
    device_sequence INTEGER NOT NULL CHECK (device_sequence >= 0),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'applied', 'conflict', 'skipped', 'rejected')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    received_at INTEGER NOT NULL CHECK (received_at >= 0),
    ciphertext_hash TEXT NOT NULL,
    envelope_json TEXT NOT NULL CHECK (json_valid(envelope_json)),
    PRIMARY KEY (owner_uid, revision_id),
    FOREIGN KEY (owner_uid) REFERENCES cloudflare_sync_owners(owner_uid) ON DELETE CASCADE,
    FOREIGN KEY (owner_uid, device_id) REFERENCES cloudflare_sync_devices(owner_uid, device_id) ON DELETE CASCADE,
    UNIQUE (owner_uid, device_id, device_sequence),
    CHECK (revision_id GLOB 'patchrev_*'),
    CHECK (patch_id GLOB 'patch_*'),
    CHECK (base_revision_id IS NULL OR base_revision_id GLOB 'srev_*')
);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_patches_pending
    ON cloudflare_sync_patches(owner_uid, status, received_at);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_patches_base
    ON cloudflare_sync_patches(owner_uid, base_revision_id, status);

CREATE TABLE IF NOT EXISTS cloudflare_sync_patch_apply_decisions (
    owner_uid TEXT NOT NULL,
    patch_revision_id TEXT NOT NULL,
    desktop_device_id TEXT NOT NULL,
    source_patch_device_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('applied', 'conflict', 'skipped')),
    reason TEXT NOT NULL,
    decided_at INTEGER NOT NULL CHECK (decided_at >= 0),
    decision_json TEXT NOT NULL CHECK (json_valid(decision_json)),
    PRIMARY KEY (owner_uid, patch_revision_id),
    FOREIGN KEY (owner_uid, patch_revision_id) REFERENCES cloudflare_sync_patches(owner_uid, revision_id) ON DELETE CASCADE,
    FOREIGN KEY (owner_uid, desktop_device_id) REFERENCES cloudflare_sync_devices(owner_uid, device_id) ON DELETE CASCADE,
    FOREIGN KEY (owner_uid, source_patch_device_id) REFERENCES cloudflare_sync_devices(owner_uid, device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cloudflare_sync_device_sequences (
    owner_uid TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_sequence INTEGER NOT NULL CHECK (device_sequence >= 0),
    operation TEXT NOT NULL,
    document_id TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (owner_uid, device_id, device_sequence),
    FOREIGN KEY (owner_uid, device_id) REFERENCES cloudflare_sync_devices(owner_uid, device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_device_sequences_document
    ON cloudflare_sync_device_sequences(owner_uid, device_id, operation, document_id);

CREATE TABLE IF NOT EXISTS cloudflare_sync_rate_limits (
    owner_uid TEXT NOT NULL,
    device_id TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    action TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL CHECK (bucket_ms >= 0),
    count INTEGER NOT NULL CHECK (count >= 0),
    first_seen_at INTEGER NOT NULL CHECK (first_seen_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    PRIMARY KEY (owner_uid, device_id, ip_hash, action, bucket_ms)
);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_rate_limits_owner_bucket
    ON cloudflare_sync_rate_limits(owner_uid, bucket_ms, action);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_rate_limits_ip_bucket
    ON cloudflare_sync_rate_limits(ip_hash, bucket_ms, action);

CREATE TABLE IF NOT EXISTS cloudflare_sync_failed_signatures (
    owner_uid TEXT NOT NULL,
    device_id TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    bucket_ms INTEGER NOT NULL CHECK (bucket_ms >= 0),
    count INTEGER NOT NULL CHECK (count >= 0),
    first_seen_at INTEGER NOT NULL CHECK (first_seen_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    PRIMARY KEY (owner_uid, device_id, ip_hash, bucket_ms)
);

CREATE INDEX IF NOT EXISTS idx_cloudflare_sync_failed_signatures_ip_bucket
    ON cloudflare_sync_failed_signatures(ip_hash, bucket_ms);
