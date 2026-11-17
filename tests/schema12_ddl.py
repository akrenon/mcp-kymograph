"""The DDL of store schema 12, as ``mcp_kymograph.store._SCHEMA`` held it before schema 13 (copied
unchanged): the triage table with its ``severity`` and ``rationale`` columns. Tests build a real
store of 12 from it; nothing else."""

SCHEMA_12 = """
CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    run TEXT PRIMARY KEY,
    run_id TEXT,
    recording TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance IN ('reference', 'poison', 'real-world')),
    server TEXT NOT NULL,
    announced_server TEXT,
    server_version TEXT NOT NULL,
    server_identity_kind TEXT NOT NULL,
    launch_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    tool_content TEXT NOT NULL,
    scenario TEXT NOT NULL,
    scenario_digest TEXT NOT NULL,
    isolation TEXT NOT NULL,
    sandbox_image TEXT,
    target_image TEXT,
    statements TEXT NOT NULL,
    wall_clock_utc TEXT,
    state TEXT NOT NULL
        CHECK (state IN ('complete', 'incomplete', 'server_failed', 'sandbox_failed',
                         'call_failed')),
    problem_count INTEGER NOT NULL,
    problems TEXT NOT NULL,
    causes TEXT NOT NULL,
    truncations TEXT NOT NULL,
    rules INTEGER NOT NULL,
    engagement_id_declared TEXT,
    engagement_digest TEXT,
    engagement_declared TEXT,
    endpoint_certificates TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    server TEXT NOT NULL,
    server_version TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    scenario TEXT NOT NULL,
    statement TEXT NOT NULL,
    locator TEXT NOT NULL,
    signal TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance IN ('reference', 'poison', 'real-world'))
);
CREATE TABLE IF NOT EXISTS sightings (
    finding INTEGER NOT NULL REFERENCES findings (id),
    run TEXT NOT NULL REFERENCES runs (run),
    path TEXT NOT NULL,
    message_seq INTEGER NOT NULL,
    normalized INTEGER NOT NULL,
    UNIQUE (finding, run, path, message_seq)
);
CREATE TABLE IF NOT EXISTS fleets (
    fleet TEXT PRIMARY KEY,
    started_utc TEXT NOT NULL,
    finished_utc TEXT NOT NULL,
    manifest_source TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    tool_content TEXT NOT NULL,
    isolation TEXT NOT NULL,
    sandbox_image TEXT,
    target_image TEXT,
    parallel INTEGER NOT NULL,
    processed TEXT NOT NULL,
    digest TEXT NOT NULL,
    complete INTEGER NOT NULL,
    problems TEXT NOT NULL,
    rules INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_results (
    fleet TEXT NOT NULL REFERENCES fleets (fleet),
    entry TEXT NOT NULL,
    scenario TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance IN ('reference', 'poison', 'real-world')),
    state TEXT NOT NULL CHECK (state IN ('complete', 'incomplete', 'server_failed',
                                         'sandbox_failed', 'call_failed', 'refused',
                                         'unfiled')),
    exit_code INTEGER,
    run TEXT REFERENCES runs (run),
    problems TEXT NOT NULL,
    causes TEXT NOT NULL,
    UNIQUE (fleet, entry, scenario)
);
CREATE TABLE IF NOT EXISTS triage (
    id INTEGER PRIMARY KEY,
    identity TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'customer')),
    status TEXT NOT NULL
        CHECK (status IN ('open', 'confirmed', 'false_positive', 'accepted',
                          'fixed_pending_recheck', 'fixed', 'intentional', 'question')),
    severity TEXT,
    rationale TEXT NOT NULL CHECK (rationale <> ''),
    author TEXT NOT NULL CHECK (author <> ''),
    at_utc TEXT NOT NULL,
    engagement_digest TEXT,
    supersedes INTEGER REFERENCES triage (id),
    CHECK (status <> 'intentional' OR role = 'customer'),
    CHECK (status <> 'fixed' OR role = 'operator')
);
CREATE INDEX IF NOT EXISTS triage_by_identity ON triage (identity, role, id);
-- A decision is never changed and never taken back: a second one is a second row.
CREATE TRIGGER IF NOT EXISTS triage_rows_are_not_changed BEFORE UPDATE ON triage
BEGIN
    SELECT RAISE(ABORT, 'refused: a triage row is never changed; a new decision is a new row');
END;
CREATE TRIGGER IF NOT EXISTS triage_rows_are_not_deleted BEFORE DELETE ON triage
BEGIN
    SELECT RAISE(ABORT, 'refused: a triage row is never deleted');
END;
CREATE TABLE IF NOT EXISTS bundles (
    index_digest TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    packed_utc TEXT NOT NULL,
    derived_from TEXT,
    engagement_digest TEXT
);
"""
